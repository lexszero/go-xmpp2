// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
	StanzaHandlers map[string]func(*xml.Name) interface{}
	// If non-nil, will be called once to start the filter
	// running. RecvFilter intercepts incoming messages on their
	// way from the remote server to the application; SendFilter
	// intercepts messages going the other direction.
	RecvFilter Filter
	SendFilter Filter
}

// Allows the user to override the TLS configuration.
var TlsConfig tls.Config

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
	handlers     chan *stanzaHandler
	inputControl chan int
	// Incoming XMPP stanzas from the remote will be published on
	// this channel. Information which is used by this library to
	// set up the XMPP stream will not appear here.
	In <-chan Stanza
	// Outgoing XMPP stanzas to the server should be sent to this
	// channel.
	Out    chan<- Stanza
	xmlOut chan<- interface{}
	// The client's roster is also known as the buddy list. It's
	// the set of contacts which are known to this JID, or which
	// this JID is known to.
	Roster Roster
	// Features advertised by the remote. This will be updated
	// asynchronously as new features are received throughout the
	// connection process. It should not be updated once
	// StartSession() returns.
	Features  *Features
	sendFilterAdd, recvFilterAdd chan Filter
}

// Connect to the appropriate server and authenticate as the given JID
// with the given password. This function will return as soon as a TCP
// connection has been established, but before XMPP stream negotiation
// has completed. The negotiation will occur asynchronously, and any
// send operation to Client.Out will block until negotiation (resource
// binding) is complete.
func NewClient(jid *JID, password string, exts []Extension) (*Client, error) {
	// Include the mandatory extensions.
	roster := newRosterExt()
	exts = append(exts, roster.Extension)
	exts = append(exts, bindExt)

	// Resolve the domain in the JID.
	_, srvs, err := net.LookupSRV(clientSrv, "tcp", jid.Domain)
	if err != nil {
		return nil, errors.New("LookupSrv " + jid.Domain +
			": " + err.Error())
	}

	var tcp *net.TCPConn
	for _, srv := range srvs {
		addrStr := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
		addr, err := net.ResolveTCPAddr("tcp", addrStr)
		if err != nil {
			err = fmt.Errorf("ResolveTCPAddr(%s): %s",
				addrStr, err.Error())
			continue
		}
		tcp, err = net.DialTCP("tcp", nil, addr)
		if err == nil {
			break
		}
		err = fmt.Errorf("DialTCP(%s): %s", addr, err)
	}
	if tcp == nil {
		return nil, err
	}

	cl := new(Client)
	cl.Roster = *roster
	cl.password = password
	cl.Jid = *jid
	cl.socket = tcp
	cl.handlers = make(chan *stanzaHandler, 100)
	cl.inputControl = make(chan int)

	extStanza := make(map[string]func(*xml.Name) interface{})
	for _, ext := range exts {
		for k, v := range ext.StanzaHandlers {
			extStanza[k] = v
		}
	}

	// Start the transport handler, initially unencrypted.
	recvReader, recvWriter := io.Pipe()
	sendReader, sendWriter := io.Pipe()
	go cl.readTransport(recvWriter)
	go cl.writeTransport(sendReader)

	// Start the reader and writer that convert to and from XML.
	recvXml := make(chan interface{})
	go readXml(recvReader, recvXml, extStanza)
	sendXml := make(chan interface{})
	cl.xmlOut = sendXml
	go writeXml(sendWriter, sendXml)

	// Start the reader and writer that convert between XML and
	// XMPP stanzas.
	recvRawXmpp := make(chan Stanza)
	go cl.readStream(recvXml, recvRawXmpp)
	sendRawXmpp := make(chan Stanza)
	go writeStream(sendXml, sendRawXmpp, cl.inputControl)

	// Start the manager for the filters that can modify what the
	// app sees.
	recvFiltXmpp := make(chan Stanza)
	cl.In = recvFiltXmpp
	go filterMgr(cl.recvFilterAdd, recvRawXmpp, recvFiltXmpp)
	sendFiltXmpp := make(chan Stanza)
	cl.Out = sendFiltXmpp
	go filterMgr(cl.sendFilterAdd, sendFiltXmpp, sendFiltXmpp)

	// Initial handshake.
	hsOut := &stream{To: jid.Domain, Version: XMPPVersion}
	cl.xmlOut <- hsOut

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
	cl.inputControl <- 1
}

// Start an XMPP session. A typical XMPP client should call this
// immediately after creating the Client in order to start the
// session, retrieve the roster, and broadcast an initial
// presence. The presence can be as simple as a newly-initialized
// Presence struct.  See RFC 3921, Section 3. After calling this, a
// normal client will want to call Roster.Update().
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
	cl.HandleStanza(id, f)
	cl.Out <- iq

	// Now wait until the callback is called.
	if err := <-ch; err != nil {
		return err
	}
	if pr != nil {
		cl.Out <- pr
	}
	return nil
}
