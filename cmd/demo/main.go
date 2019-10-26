package main

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"net"

	"github.com/zhangyoufu/sni"
)

func main() {
	ln, err := net.Listen("tcp4", "127.0.0.1:8443")
	if err != nil {
		panic(err)
	}
	log.Print("listening on ", ln.Addr())
	for {
		conn, err := ln.Accept()
		go func(conn net.Conn) {
			defer conn.Close()
			if err != nil {
				log.Print(err)
				return
			}
			hostname, rcvd, err := sni.ReadHostname(conn)
			if err != nil {
				log.Print(err)
				return
			}
			data, err := ioutil.ReadAll(rcvd)
			_ = rcvd.Close()
			if err != nil {
				log.Print(err)
				return
			}
			log.Printf("%s\n%s", hostname, hex.Dump(data))
		}(conn)
	}
}
