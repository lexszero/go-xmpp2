// This layer of the XMPP protocol reads XMLish structures and
// responds to them. It negotiates TLS and authentication.

package xmpp

import (
	"encoding/xml"
	"crypto/tls"
	"time"
)

// Callback to handle a stanza with a particular id.
type stanzaHandler struct {
	id string
	// Return true means pass this to the application
	f func(Stanza) bool
}

func (cl *Client) readStream(srvIn <-chan interface{}, cliOut chan<- Stanza) {
	defer close(cliOut)

	handlers := make(map[string]func(Stanza) bool)
Loop:
	for {
		select {
		case h := <-cl.handlers:
			handlers[h.id] = h.f
		case x, ok := <-srvIn:
			if !ok {
				break Loop
			}
			switch obj := x.(type) {
			case *stream:
				handleStream(obj)
			case *streamError:
				cl.handleStreamError(obj)
			case *Features:
				cl.handleFeatures(obj)
			case *starttls:
				cl.handleTls(obj)
			case *auth:
				cl.handleSasl(obj)
			case Stanza:
				send := true
				id := obj.GetHeader().Id
				if handlers[id] != nil {
					f := handlers[id]
					delete(handlers, id)
					send = f(obj)
				}
				if send {
					cliOut <- obj
				}
			default:
				Warn.Logf("Unhandled non-stanza: %T %#v", x, x)
			}
		}
	}
}

// This loop is paused until resource binding is complete. Otherwise
// the app might inject something inappropriate into our negotiations
// with the server. The control channel controls this loop's
// activity.
func writeStream(srvOut chan<- interface{}, cliIn <-chan Stanza,
	control <-chan int) {
	defer close(srvOut)

	var input <-chan Stanza
Loop:
	for {
		select {
		case status := <-control:
			switch status {
			case 0:
				input = nil
			case 1:
				input = cliIn
			case -1:
				break Loop
			}
		case x, ok := <-input:
			if !ok {
				break Loop
			}
			if x == nil {
				Info.Log("Refusing to send nil stanza")
				continue
			}
			srvOut <- x
		}
	}
}

func handleStream(ss *stream) {
}

func (cl *Client) handleStreamError(se *streamError) {
	Info.Logf("Received stream error: %v", se)
	cl.socket.Close()
}

func (cl *Client) handleFeatures(fe *Features) {
	cl.Features = fe
	if fe.Starttls != nil {
		start := &starttls{XMLName: xml.Name{Space: NsTLS,
			Local: "starttls"}}
		cl.sendXml <- start
		return
	}

	if len(fe.Mechanisms.Mechanism) > 0 {
		cl.chooseSasl(fe)
		return
	}

	if fe.Bind != nil {
		cl.bind(fe.Bind)
		return
	}
}

// readTransport() is running concurrently. We need to stop it,
// negotiate TLS, then start it again. It calls waitForSocket() in
// its inner loop; see below.
func (cl *Client) handleTls(t *starttls) {
	tcp := cl.socket

	// Set the socket to nil, and wait for the reader routine to
	// signal that it's paused.
	cl.socket = nil
	cl.socketSync.Add(1)
	cl.socketSync.Wait()

	// Negotiate TLS with the server.
	tls := tls.Client(tcp, &cl.tlsConfig)

	// Make the TLS connection available to the reader, and wait
	// for it to signal that it's working again.
	cl.socketSync.Add(1)
	cl.socket = tls
	cl.socketSync.Wait()

	Info.Log("TLS negotiation succeeded.")
	cl.Features = nil

	// Now re-send the initial handshake message to start the new
	// session.
	hsOut := &stream{To: cl.Jid.Domain, Version: XMPPVersion}
	cl.sendXml <- hsOut
}

// Synchronize with handleTls(). Called from readTransport() when
// cl.socket is nil.
func (cl *Client) waitForSocket() {
	// Signal that we've stopped reading from the socket.
	cl.socketSync.Done()

	// Wait until the socket is available again.
	for cl.socket == nil {
		time.Sleep(1e8)
	}

	// Signal that we're going back to the read loop.
	cl.socketSync.Done()
}

// Register a callback to handle the next XMPP stanza (iq, message, or
// presence) with a given id. The provided function will not be called
// more than once. If it returns false, the stanza will not be made
// available on the normal Client.In channel. The stanza handler
// must not read from that channel, as deliveries on it cannot proceed
// until the handler returns true or false.
func (cl *Client) HandleStanza(id string, f func(Stanza) bool) {
	h := &stanzaHandler{id: id, f: f}
	cl.handlers <- h
}

// Send a request to bind a resource. RFC 3920, section 7.
func (cl *Client) bind(bindAdv *bindIq) {
	res := cl.Jid.Resource
	bindReq := &bindIq{}
	if res != "" {
		bindReq.Resource = &res
	}
	msg := &Iq{Header: Header{Type: "set", Id: NextId(),
		Nested: []interface{}{bindReq}}}
	f := func(st Stanza) bool {
		iq, ok := st.(*Iq)
		if !ok {
			Warn.Log("non-iq response")
		}
		if iq.Type == "error" {
			Warn.Log("Resource binding failed")
			return false
		}
		var bindRepl *bindIq
		for _, ele := range iq.Nested {
			if b, ok := ele.(*bindIq); ok {
				bindRepl = b
				break
			}
		}
		if bindRepl == nil {
			Warn.Logf("Bad bind reply: %#v", iq)
			return false
		}
		jidStr := bindRepl.Jid
		if jidStr == nil || *jidStr == "" {
			Warn.Log("Can't bind empty resource")
			return false
		}
		jid := new(JID)
		if err := jid.Set(*jidStr); err != nil {
			Warn.Logf("Can't parse JID %s: %s", *jidStr, err)
			return false
		}
		cl.Jid = *jid
		Info.Logf("Bound resource: %s", cl.Jid.String())
		cl.bindDone()
		return false
	}
	cl.HandleStanza(msg.Id, f)
	cl.sendXml <- msg
}