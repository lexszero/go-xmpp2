// This layer of the XMPP protocol translates between bytes and XMLish
// structures.

package xmpp

import (
	"io"
	"reflect"
	"encoding/xml"
	"fmt"
	"strings"
)

func readXml(r io.Reader, ch chan<- interface{},
	extStanza map[xml.Name]reflect.Type) {
	if _, ok := Debug.(*noLog); !ok {
		pr, pw := io.Pipe()
		go tee(r, pw, "S: ")
		r = pr
	}
	defer close(ch)

	// This trick loads our namespaces into the parser.
	nsstr := fmt.Sprintf(`<a xmlns="%s" xmlns:stream="%s">`,
		NsClient, NsStream)
	nsrdr := strings.NewReader(nsstr)
	p := xml.NewDecoder(io.MultiReader(nsrdr, r))
	p.Token()

Loop:
	for {
		// Sniff the next token on the stream.
		t, err := p.Token()
		if t == nil {
			if err != io.EOF {
				Warn.Logf("read: %s", err)
			}
			break
		}
		var se xml.StartElement
		var ok bool
		if se, ok = t.(xml.StartElement); !ok {
			continue
		}

		// Allocate the appropriate structure for this token.
		var obj interface{}
		switch se.Name.Space + " " + se.Name.Local {
		case NsStream + " stream":
			st, err := parseStream(se)
			if err != nil {
				Warn.Logf("unmarshal stream: %s", err)
				break Loop
			}
			ch <- st
			continue
		case "stream error", NsStream + " error":
			obj = &streamError{}
		case NsStream + " features":
			obj = &Features{}
		case NsTLS + " proceed", NsTLS + " failure":
			obj = &starttls{}
		case NsSASL + " challenge", NsSASL + " failure",
			NsSASL + " success":
			obj = &auth{}
		case NsClient + " iq":
			obj = &Iq{}
		case NsClient + " message":
			obj = &Message{}
		case NsClient + " presence":
			obj = &Presence{}
		default:
			obj = &Generic{}
			Info.Logf("Ignoring unrecognized: %s %s", se.Name.Space,
				se.Name.Local)
		}

		// Read the complete XML stanza.
		err = p.DecodeElement(obj, &se)
		if err != nil {
			Warn.Logf("unmarshal: %s", err)
			break Loop
		}

		// If it's a Stanza, we try to unmarshal its innerxml
		// into objects of the appropriate respective
		// types. This is specified by our extensions.
		if st, ok := obj.(Stanza); ok {
			err = parseExtended(st.GetHeader(), extStanza)
			if err != nil {
				Warn.Logf("ext unmarshal: %s", err)
				break Loop
			}
		}

		// Put it on the channel.
		ch <- obj
	}
}

func parseExtended(st *Header, extStanza map[xml.Name]reflect.Type) error {
	// Now parse the stanza's innerxml to find the string that we
	// can unmarshal this nested element from.
	reader := strings.NewReader(st.Innerxml)
	p := xml.NewDecoder(reader)
	for {
		t, err := p.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if se, ok := t.(xml.StartElement); ok {
			if typ, ok := extStanza[se.Name]; ok {
				nested := reflect.New(typ).Interface()

				// Unmarshal the nested element and
				// stuff it back into the stanza.
				err := p.DecodeElement(nested, &se)
				if err != nil {
					return err
				}
				st.Nested = append(st.Nested, nested)
			}
		}
	}

	return nil
}

func writeXml(w io.Writer, ch <-chan interface{}) {
	if _, ok := Debug.(*noLog); !ok {
		pr, pw := io.Pipe()
		go tee(pr, w, "C: ")
		w = pw
	}
	defer func(w io.Writer) {
		if c, ok := w.(io.Closer); ok {
			c.Close()
		}
	}(w)

	enc := xml.NewEncoder(w)

	for obj := range ch {
		if st, ok := obj.(*stream); ok {
			_, err := w.Write([]byte(st.String()))
			if err != nil {
				Warn.Logf("write: %s", err)
			}
		} else {
			err := enc.Encode(obj)
			if err != nil {
				Warn.Logf("marshal: %s", err)
				break
			}
		}
	}
}
