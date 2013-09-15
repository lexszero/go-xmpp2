// This layer of the XMPP protocol reads XMLish structures and
// responds to them. It negotiates TLS and authentication.

package xmpp

import (
	"encoding/xml"
	"fmt"
)

// Callback to handle a stanza with a particular id.
type callback struct {
	id string
	// Return true means pass this to the application
	f func(Stanza) bool
}

// Receive XMLish structures, handle all the stream-related ones, and
// send XMPP stanzas on to the client.
func (cl *Client) recvStream(recvXml <-chan interface{}, sendXmpp chan<- Stanza) {
	defer close(sendXmpp)

	handlers := make(map[string]func(Stanza) bool)
Loop:
	for {
		select {
		case h := <-cl.handlers:
			handlers[h.id] = h.f
		case x, ok := <-recvXml:
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
					sendXmpp <- obj
				}
			default:
				Warn.Logf("Unhandled non-stanza: %T %#v", x, x)
			}
		}
	}
}

// Receive XMPP stanzas from the client and send them on to the
// remote. Don't allow the client to send us any stanzas until
// negotiation has completed.  This loop is paused until resource
// binding is complete. Otherwise the app might inject something
// inappropriate into our negotiations with the server. The control
// channel controls this loop's activity.
func sendStream(sendXml chan<- interface{}, recvXmpp <-chan Stanza,
	control <-chan sendCmd) {
	defer close(sendXml)

	var input <-chan Stanza
	for {
		select {
		case cmd := <-control:
			switch cmd {
			case sendDeny:
				input = nil
			case sendAllow:
				input = recvXmpp
			case sendAbort:
				return
			default:
				panic(fmt.Sprintf("unknown cmd %d", cmd))
			}
		case x, ok := <-input:
			if !ok {
				return
			}
			if x == nil {
				Info.Log("Refusing to send nil stanza")
				continue
			}
			sendXml <- x
		}
	}
}

func handleStream(ss *stream) {
}

func (cl *Client) handleStreamError(se *streamError) {
	Info.Logf("Received stream error: %v", se)
	cl.inputControl <- sendAbort
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

func (cl *Client) handleTls(t *starttls) {
	cl.layer1.startTls(&cl.tlsConfig)

	// Now re-send the initial handshake message to start the new
	// session.
	cl.sendXml <- &stream{To: cl.Jid.Domain, Version: XMPPVersion}
}

// Register a callback to handle the next XMPP stanza (iq, message, or
// presence) with a given id. The provided function will not be called
// more than once. If it returns false, the stanza will not be made
// available on the normal Client.Recv channel. The callback must not
// read from that channel, as deliveries on it cannot proceed until
// the handler returns true or false.
func (cl *Client) SetCallback(id string, f func(Stanza) bool) {
	h := &callback{id: id, f: f}
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
	cl.SetCallback(msg.Id, f)
	cl.sendXml <- msg
}
