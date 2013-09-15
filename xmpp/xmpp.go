// This package implements a simple XMPP client according to RFCs 3920
// and 3921, plus the various XEPs at http://xmpp.org/protocols/. The
// implementation is structured as a stack of layers, with TCP at the
// bottom and the application at the top. The application receives and
// sends structures representing XMPP stanzas. Additional stanza
// parsers can be inserted into the stack of layers as extensions.
package xmpp

import (
	"bytes"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"sync"
)

const (
	// Version of RFC 3920 that we implement.
	XMPPVersion = "1.0"

	// Various XML namespaces.
	NsClient  = "jabber:client"
	NsStreams = "urn:ietf:params:xml:ns:xmpp-streams"
	NsStream  = "http://etherx.jabber.org/streams"
	NsTLS     = "urn:ietf:params:xml:ns:xmpp-tls"
	NsSASL    = "urn:ietf:params:xml:ns:xmpp-sasl"
	NsBind    = "urn:ietf:params:xml:ns:xmpp-bind"
	NsSession = "urn:ietf:params:xml:ns:xmpp-session"
	NsRoster  = "jabber:iq:roster"

	// DNS SRV names
	serverSrv = "xmpp-server"
	clientSrv = "xmpp-client"
)

// Flow control for preventing sending stanzas until negotiation has
// completed.
type sendCmd bool

var (
	sendAllow sendCmd = true
	sendDeny  sendCmd = false
)

// A filter can modify the XMPP traffic to or from the remote
// server. It's part of an Extension. The filter function will be
// called in a new goroutine, so it doesn't need to return. The filter
// should close its output when its input is closed.
type Filter func(in <-chan Stanza, out chan<- Stanza)

// Extensions can add stanza filters and/or new XML element types.
type Extension struct {
	// Maps from an XML namespace to a function which constructs a
	// structure to hold the contents of stanzas in that
	// namespace.
	StanzaHandlers map[xml.Name]reflect.Type
	// If non-nil, will be called once to start the filter
	// running. RecvFilter intercepts incoming messages on their
	// way from the remote server to the application; SendFilter
	// intercepts messages going the other direction.
	RecvFilter Filter
	SendFilter Filter
}

// The client in a client-server XMPP connection.
type Client struct {
	// This client's JID. This will be updated asynchronously by
	// the time StartSession() returns.
	Jid          JID
	password     string
	socket       net.Conn
	socketSync   sync.WaitGroup
	saslExpected string
	authDone     bool
	handlers     chan *callback
	inputControl chan sendCmd
	// Incoming XMPP stanzas from the remote will be published on
	// this channel. Information which is used by this library to
	// set up the XMPP stream will not appear here.
	Recv <-chan Stanza
	// Outgoing XMPP stanzas to the server should be sent to this
	// channel.
	Send    chan<- Stanza
	sendXml chan<- interface{}
	// The client's roster is also known as the buddy list. It's
	// the set of contacts which are known to this JID, or which
	// this JID is known to.
	Roster Roster
	// Features advertised by the remote. This will be updated
	// asynchronously as new features are received throughout the
	// connection process. It should not be updated once
	// StartSession() returns.
	Features                     *Features
	sendFilterAdd, recvFilterAdd chan Filter
	// Allows the user to override the TLS configuration.
	tlsConfig tls.Config
}

// Connect to the appropriate server and authenticate as the given JID
// with the given password. This function will return as soon as a TCP
// connection has been established, but before XMPP stream negotiation
// has completed. The negotiation will occur asynchronously, and any
// send operation to Client.Send will block until negotiation
// (resource binding) is complete. The caller must immediately start
// reading from Client.Recv.
func NewClient(jid *JID, password string, tlsconf tls.Config, exts []Extension) (*Client, error) {
	// Include the mandatory extensions.
	roster := newRosterExt()
	exts = append(exts, roster.Extension)
	exts = append(exts, bindExt)

	// Resolve the domain in the JID.
	_, srvs, err := net.LookupSRV(clientSrv, "tcp", jid.Domain)
	if err != nil {
		return nil, fmt.Errorf("LookupSrv %s: %v", jid.Domain, err)
	}
	if len(srvs) == 0 {
		return nil, fmt.Errorf("LookupSrv %s: no results", jid.Domain)
	}

	var tcp *net.TCPConn
	for _, srv := range srvs {
		addrStr := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
		var addr *net.TCPAddr
		addr, err = net.ResolveTCPAddr("tcp", addrStr)
		if err != nil {
			err = fmt.Errorf("ResolveTCPAddr(%s): %s",
				addrStr, err.Error())
			continue
		}
		tcp, err = net.DialTCP("tcp", nil, addr)
		if tcp != nil {
			break
		}
	}
	if tcp == nil {
		return nil, err
	}

	cl := new(Client)
	cl.Roster = *roster
	cl.password = password
	cl.Jid = *jid
	cl.socket = tcp
	cl.handlers = make(chan *callback, 100)
	cl.inputControl = make(chan sendCmd)
	cl.tlsConfig = tlsconf
	cl.sendFilterAdd = make(chan Filter)
	cl.recvFilterAdd = make(chan Filter)

	extStanza := make(map[xml.Name]reflect.Type)
	for _, ext := range exts {
		for k, v := range ext.StanzaHandlers {
			if _, ok := extStanza[k]; ok {
				return nil, fmt.Errorf("duplicate handler %s",
					k)
			}
			extStanza[k] = v
		}
	}

	// Start the transport handler, initially unencrypted.
	recvReader, recvWriter := io.Pipe()
	sendReader, sendWriter := io.Pipe()
	go cl.recvTransport(recvWriter)
	go cl.sendTransport(sendReader)

	// Start the reader and writer that convert to and from XML.
	recvXmlCh := make(chan interface{})
	go recvXml(recvReader, recvXmlCh, extStanza)
	sendXmlCh := make(chan interface{})
	cl.sendXml = sendXmlCh
	go sendXml(sendWriter, sendXmlCh)

	// Start the reader and writer that convert between XML and
	// XMPP stanzas.
	recvRawXmpp := make(chan Stanza)
	go cl.recvStream(recvXmlCh, recvRawXmpp)
	sendRawXmpp := make(chan Stanza)
	go sendStream(sendXmlCh, sendRawXmpp, cl.inputControl)

	// Start the manager for the filters that can modify what the
	// app sees.
	recvFiltXmpp := make(chan Stanza)
	cl.Recv = recvFiltXmpp
	go filterMgr(cl.recvFilterAdd, recvRawXmpp, recvFiltXmpp)
	sendFiltXmpp := make(chan Stanza)
	cl.Send = sendFiltXmpp
	go filterMgr(cl.sendFilterAdd, sendFiltXmpp, sendRawXmpp)
	// Set up the initial filters.
	for _, ext := range exts {
		cl.AddRecvFilter(ext.RecvFilter)
		cl.AddSendFilter(ext.SendFilter)
	}

	// Initial handshake.
	hsOut := &stream{To: jid.Domain, Version: XMPPVersion}
	cl.sendXml <- hsOut

	return cl, nil
}

func tee(r io.Reader, w io.Writer, prefix string) {
	defer func(w io.Writer) {
		if c, ok := w.(io.Closer); ok {
			c.Close()
		}
	}(w)

	buf := bytes.NewBuffer([]uint8(prefix))
	for {
		var c [1]byte
		n, _ := r.Read(c[:])
		if n == 0 {
			break
		}
		n, _ = w.Write(c[:n])
		if n == 0 {
			break
		}
		buf.Write(c[:n])
		if c[0] == '\n' || c[0] == '>' {
			Debug.Log(buf)
			buf = bytes.NewBuffer([]uint8(prefix))
		}
	}
	leftover := buf.String()
	if leftover != "" {
		Debug.Log(buf)
	}
}

// bindDone is called when we've finished resource binding (and all
// the negotiations that precede it). Now we can start accepting
// traffic from the app.
func (cl *Client) bindDone() {
	cl.inputControl <- sendAllow
}

// Start an XMPP session. A typical XMPP client should call this
// immediately after creating the Client in order to start the session
// and broadcast an initial presence. The presence can be as simple as
// a newly-initialized Presence struct.  See RFC 3921, Section
// 3. After calling this, a normal client should call Roster.Update().
func (cl *Client) StartSession(pr *Presence) error {
	id := NextId()
	iq := &Iq{Header: Header{To: cl.Jid.Domain, Id: id, Type: "set",
		Nested: []interface{}{Generic{XMLName: xml.Name{Space: NsSession, Local: "session"}}}}}
	ch := make(chan error)
	f := func(st Stanza) bool {
		iq, ok := st.(*Iq)
		if !ok {
			Warn.Log("iq reply not iq; can't start session")
			ch <- errors.New("bad session start reply")
			return false
		}
		if iq.Type == "error" {
			Warn.Logf("Can't start session: %v", iq)
			ch <- iq.Error
			return false
		}
		ch <- nil
		return false
	}
	cl.SetCallback(id, f)
	cl.Send <- iq

	// Now wait until the callback is called.
	if err := <-ch; err != nil {
		return err
	}
	if pr != nil {
		cl.Send <- pr
	}
	return nil
}
