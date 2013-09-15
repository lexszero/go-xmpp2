// The lowest level of XMPP protocol, where TLS is applied after the
// initial handshake.

package xmpp

import (
	"io"
	"net"
	"time"
)

func (cl *Client) recvTransport(w io.WriteCloser) {
	defer w.Close()
	p := make([]byte, 1024)
	for {
		if cl.socket == nil {
			cl.waitForSocket()
		}
		cl.socket.SetReadDeadline(time.Now().Add(time.Second))
		nr, err := cl.socket.Read(p)
		if nr == 0 {
			if errno, ok := err.(*net.OpError); ok {
				if errno.Timeout() {
					continue
				}
			}
			Warn.Logf("read: %s", err)
			break
		}
		nw, err := w.Write(p[:nr])
		if nw < nr {
			Warn.Logf("read: %s", err)
			break
		}
	}
}

func (cl *Client) sendTransport(r io.Reader) {
	defer cl.socket.Close()
	p := make([]byte, 1024)
	for {
		nr, err := r.Read(p)
		if nr == 0 {
			Warn.Logf("write: %s", err)
			break
		}
		nw, err := cl.socket.Write(p[:nr])
		if nw < nr {
			Warn.Logf("write: %s", err)
			break
		}
	}
}
