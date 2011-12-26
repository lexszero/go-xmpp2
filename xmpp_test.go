// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmpp

import (
	"bytes"
	"reflect"
	"strings"
	"sync"
	"testing"
	"xml"
)

func TestReadError(t *testing.T) {
	r := strings.NewReader(`<stream:error><bad-foo/></stream:error>`)
	ch := make(chan interface{})
	go readXml(r, ch, false)
	x := <- ch
	se, ok := x.(*StreamError)
	if !ok {
		t.Fatalf("not StreamError: %v", reflect.TypeOf(x))
	}
	assertEquals(t, "bad-foo", se.Any.XMLName.Local)
	assertEquals(t, "", se.Any.XMLName.Space)
	if se.Text != nil {
		t.Errorf("text not nil: %v", se.Text)
	}

	r = strings.NewReader(`<stream:error><bad-foo/>` +
		`<text xml:lang="en" xmlns="` + nsStreams +
		`">Error text</text></stream:error>`)
	ch = make(chan interface{})
	go readXml(r, ch, false)
	x = <- ch
	se, ok = x.(*StreamError)
	if !ok {
		t.Fatalf("not StreamError: %v", reflect.TypeOf(x))
	}
	assertEquals(t, "bad-foo", se.Any.XMLName.Local)
	assertEquals(t, "", se.Any.XMLName.Space)
	assertEquals(t, "Error text", se.Text.Text)
	assertEquals(t, "en", se.Text.Lang)
}

func TestReadStream(t *testing.T) {
	r := strings.NewReader(`<stream:stream to="foo.com" ` +
		`from="bar.org" id="42"` +
		`xmlns="jabber:client" xmlns:stream="` + nsStream +
		`" version="1.0">`)
	ch := make(chan interface{})
	go readXml(r, ch, false)
	x := <- ch
	ss, ok := x.(*Stream)
	if !ok {
		t.Fatalf("not Stream: %v", reflect.TypeOf(x))
	}
	assertEquals(t, "foo.com", ss.To)
	assertEquals(t, "bar.org", ss.From)
	assertEquals(t, "42", ss.Id)
	assertEquals(t, "1.0", ss.Version)
}

func testWrite(obj interface{}) string {
	w := bytes.NewBuffer(nil)
	ch := make(chan interface{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		writeXml(w, ch, true)
	}()
	ch <- obj
	close(ch)
	wg.Wait()
	return w.String()
}

func TestWriteError(t *testing.T) {
	se := &StreamError{Any: definedCondition{XMLName:
			xml.Name{Local: "blah"}}}
	str := testWrite(se)
	exp := `<stream:error><blah></blah></stream:error>`
	assertEquals(t, exp, str)

	se = &StreamError{Any: definedCondition{XMLName:
			xml.Name{Space: nsStreams, Local: "foo"}},
		Text: &errText{Lang: "ru", Text: "Пошёл ты"}}
	str = testWrite(se)
	exp = `<stream:error><foo xmlns="` + nsStreams +
		`"></foo><text xmlns="` + nsStreams +
		`" xml:lang="ru">Пошёл ты</text></stream:error>`
	assertEquals(t, exp, str)
}

func TestWriteStream(t *testing.T) {
	ss := &Stream{To: "foo.org", From: "bar.com", Id: "42", Lang:
		"en", Version: "1.0"}
	str := testWrite(ss)
	exp := `<stream:stream xmlns="jabber:client"` +
		` xmlns:stream="` + nsStream + `" to="foo.org"` +
		` from="bar.com" id="42" xml:lang="en" version="1.0">`
	assertEquals(t, exp, str)
}
