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

// Status of the connection.
type Status int

const (
	statusUnconnected = iota
	statusConnected
	statusConnectedTls
	statusAuthenticated
	statusBound
	statusRunning
	statusShutdown
)

var (
	// The client has not yet connected, or it has been
	// disconnected from the server.
	StatusUnconnected Status = statusUnconnected
	// Initial connection established.
	StatusConnected Status = statusConnected
	// Like StatusConnected, but with TLS.
	StatusConnectedTls Status = statusConnectedTls
	// Authentication succeeded.
	StatusAuthenticated Status = statusAuthenticated
	// Resource binding complete.
	StatusBound Status = statusBound
	// Session has started and normal message traffic can be sent
	// and received.
	StatusRunning Status = statusRunning
	// The session has closed, or is in the process of closing.
	StatusShutdown Status = statusShutdown
)

// A filter can modify the XMPP traffic to or from the remote
// server. It's part of an Extension. The filter function will be
// called in a new goroutine, so it doesn't need to return. The filter
// should close its output when its input is closed.
type Filter func(in <-chan Stanza, out chan<- Stanza)

// Extensions can add stanza filters and/or new XML element types.
type Extension struct {
	// Maps from an XML name to a structure which holds stanza
	// contents with that name.
	StanzaTypes map[xml.Name]reflect.Type
	// If non-nil, will be called once to start the filter
	// running. RecvFilter intercepts incoming messages on their
	// way from the remote server to the application; SendFilter
	// intercepts messages going the other direction.
	RecvFilter Filter
	SendFilter Filter
}

// The client in a client-server XMPP connection.
type Client struct {
	// This client's full JID, including resource
	Jid          JID
	password     string
	saslExpected string
	authDone     bool
	handlers     chan *callback
	// Incoming XMPP stanzas from the remote will be published on
	// this channel. Information which is used by this library to
	// set up the XMPP stream will not appear here.
	Recv <-chan Stanza
	// Outgoing XMPP stanzas to the server should be sent to this
	// channel.
	Send    chan<- Stanza
	sendXml chan<- interface{}
	statmgr *statmgr
	// The client's roster is also known as the buddy list. It's
	// the set of contacts which are known to this JID, or which
	// this JID is known to.
	Roster Roster
	// Features advertised by the remote.
	Features                     *Features
	sendFilterAdd, recvFilterAdd chan Filter
	tlsConfig                    tls.Config
	layer1                       *layer1
}

// Creates an XMPP client identified by the given JID, authenticating
// with the provided password and TLS config. Zero or more extensions
// may be specified. The initial presence will be broadcast. If status
// is non-nil, connection progress information will be sent on it.
func NewClient(jid *JID, password string, tlsconf tls.Config, exts []Extension,
	pr Presence, status chan<- Status) (*Client, error) {

	// Include the mandatory extensions.
	roster := newRosterExt()
	exts = append(exts, roster.Extension)
	exts = append(exts, bindExt)

	cl := new(Client)
	cl.Roster = *roster
	cl.password = password
	cl.Jid = *jid
	cl.handlers = make(chan *callback, 100)
	cl.tlsConfig = tlsconf
	cl.sendFilterAdd = make(chan Filter)
	cl.recvFilterAdd = make(chan Filter)
	cl.statmgr = newStatmgr(status)

	extStanza := make(map[xml.Name]reflect.Type)
	for _, ext := range exts {
		for k, v := range ext.StanzaTypes {
			if _, ok := extStanza[k]; ok {
				return nil, fmt.Errorf("duplicate handler %s",
					k)
			}
			extStanza[k] = v
		}
	}

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
	cl.setStatus(StatusConnected)

	// Start the transport handler, initially unencrypted.
	recvReader, recvWriter := io.Pipe()
	sendReader, sendWriter := io.Pipe()
	cl.layer1 = startLayer1(tcp, recvWriter, sendReader,
		cl.statmgr.newListener())

	// Start the reader and writer that convert to and from XML.
	recvXmlCh := make(chan interface{})
	go recvXml(recvReader, recvXmlCh, extStanza)
	sendXmlCh := make(chan interface{})
	cl.sendXml = sendXmlCh
	go sendXml(sendWriter, sendXmlCh)

	// Start the reader and writer that convert between XML and
	// XMPP stanzas.
	recvRawXmpp := make(chan Stanza)
	go cl.recvStream(recvXmlCh, recvRawXmpp, cl.statmgr.newListener())
	sendRawXmpp := make(chan Stanza)
	go sendStream(sendXmlCh, sendRawXmpp, cl.statmgr.newListener())

	// Start the managers for the filters that can modify what the
	// app sees or sends.
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

	// Wait until resource binding is complete.
	if err := cl.statmgr.awaitStatus(StatusBound); err != nil {
		return nil, err
	}

	// Forget about the password, for paranoia's sake.
	cl.password = ""

	// Initialize the session.
	id := NextId()
	iq := &Iq{Header: Header{To: cl.Jid.Domain, Id: id, Type: "set",
		Nested: []interface{}{Generic{XMLName: xml.Name{Space: NsSession, Local: "session"}}}}}
	ch := make(chan error)
	f := func(st Stanza) {
		iq, ok := st.(*Iq)
		if !ok {
			Warn.Log("iq reply not iq; can't start session")
			ch <- errors.New("bad session start reply")
		}
		if iq.Type == "error" {
			Warn.Logf("Can't start session: %v", iq)
			ch <- iq.Error
		}
		ch <- nil
	}
	cl.SetCallback(id, f)
	cl.sendXml <- iq
	// Now wait until the callback is called.
	if err := <-ch; err != nil {
		return nil, err
	}

	// This allows the client to receive stanzas.
	cl.setStatus(StatusRunning)

	// Request the roster.
	cl.Roster.update()

	// Send the initial presence.
	cl.Send <- &pr

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

func (cl *Client) Close() {
	// Shuts down the receivers:
	cl.setStatus(StatusShutdown)
	// Shuts down the senders:
	close(cl.Send)
}
