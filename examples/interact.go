// Copyright 2011 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"cjyar/xmpp"
	"flag"
	"fmt"
	"log"
	"os"
	)

// Demonstrate the API, and allow the user to interact with an XMPP
// server via the terminal.
func main() {
	var jid xmpp.JID
	flag.Var(&jid, "jid", "JID to log in as")
	var pw *string = flag.String("pw", "", "password")
	flag.Parse()
	if jid.Domain == "" || *pw == "" {
		flag.Usage()
		os.Exit(2)
	}

	c, err := xmpp.NewClient(&jid, *pw)
	if err != nil {
		log.Fatalf("NewClient(%v): %v", jid, err)
	}
	defer c.Close()

	go func(ch <-chan interface{}) {
		for obj := range ch {
			fmt.Printf("s: %v\n", obj)
		}
		fmt.Println("done reading")
	}(c.In)

	ch := make(chan interface{})
	go xmpp.ReadXml(os.Stdin, ch, false)
	for x := range ch {
		fmt.Printf("c: %v", x)
		c.Out <- x
	}
	fmt.Println("done sending")
}
