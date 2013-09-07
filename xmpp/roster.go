// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xmpp

// This file contains support for roster management, RFC 3921, Section 7.

import (
	"encoding/xml"
	"reflect"
)

// Roster query/result
type RosterQuery struct {
	XMLName xml.Name     `xml:"jabber:iq:roster query"`
	Item    []RosterItem `xml:"item"`
}

// See RFC 3921, Section 7.1.
type RosterItem struct {
	XMLName      xml.Name `xml:"jabber:iq:roster item"`
	Jid          string   `xml:"jid,attr"`
	Subscription string   `xml:"subscription,attr"`
	Name         string   `xml:"name,attr"`
	Group        []string
}

type rosterCb struct {
	id string
	cb func()
}

type Roster struct {
	Extension
	get       chan []RosterItem
	callbacks chan rosterCb
	toServer  chan Stanza
}

type rosterClient struct {
	rosterChan   <-chan []RosterItem
	rosterUpdate chan<- RosterItem
}

func (r *Roster) rosterMgr(upd <-chan Stanza) {
	roster := make(map[string]RosterItem)
	waits := make(map[string]func())
	var snapshot []RosterItem
	for {
		select {
		case stan, ok := <-upd:
			if !ok {
				return
			}
			hdr := stan.GetHeader()
			if f := waits[hdr.Id]; f != nil {
				delete(waits, hdr.Id)
				f()
			}
			iq, ok := stan.(*Iq)
			if iq.Type != "set" {
				continue
			}
			var rq *RosterQuery
			for _, ele := range iq.Nested {
				if q, ok := ele.(*RosterQuery); ok {
					rq = q
					break
				}
			}
			if rq == nil {
				continue
			}
			for _, item := range rq.Item {
				roster[item.Jid] = item
			}
			snapshot = []RosterItem{}
			for _, ri := range roster {
				snapshot = append(snapshot, ri)
			}
		case r.get <- snapshot:
		case cb := <-r.callbacks:
			waits[cb.id] = cb.cb
		}
	}
}

func (r *Roster) makeFilters() (Filter, Filter) {
	rosterUpdate := make(chan Stanza)
	go r.rosterMgr(rosterUpdate)
	recv := func(in <-chan Stanza, out chan<- Stanza) {
		defer close(out)
		for stan := range in {
			rosterUpdate <- stan
			out <- stan
		}
	}
	send := func(in <-chan Stanza, out chan<- Stanza) {
		defer close(out)
		for {
			select {
			case stan, ok := <-in:
				if !ok {
					return
				}
				out <- stan
			case stan := <-r.toServer:
				out <- stan
			}
		}
	}
	return recv, send
}

func newRosterExt() *Roster {
	r := Roster{}
	r.StanzaHandlers = make(map[xml.Name]reflect.Type)
	rName := xml.Name{Space: NsRoster, Local: "query"}
	r.StanzaHandlers[rName] = reflect.TypeOf(RosterQuery{})
	r.RecvFilter, r.SendFilter = r.makeFilters()
	r.get = make(chan []RosterItem)
	r.callbacks = make(chan rosterCb)
	r.toServer = make(chan Stanza)
	return &r
}

// Return the most recent snapshot of the roster status. This is
// updated automatically as roster updates are received from the
// server, but especially in response to calls to Update().
func (r *Roster) Get() []RosterItem {
	return <-r.get
}

// Synchronously fetch this entity's roster from the server and cache
// that information. The client can access the roster by watching for
// RosterQuery objects or by calling Get().
func (r *Roster) Update() {
	iq := &Iq{Header: Header{Type: "get", Id: NextId(),
		Nested: []interface{}{RosterQuery{}}}}
	waitchan := make(chan int)
	done := func() {
		close(waitchan)
	}
	r.waitFor(iq.Id, done)
	r.toServer <- iq
	<-waitchan
}

func (r *Roster) waitFor(id string, cb func()) {
	r.callbacks <- rosterCb{id: id, cb: cb}
}
