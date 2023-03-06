package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"time"
)

func main() {
	addrPtr := flag.String("addr", "127.0.0.1", "Destination to start scan")
	portPtr := flag.String("port", "443", "Port to scan")
	flag.Parse()
	fmt.Println("Reality Tls Scanner running: ", *addrPtr, ":", *portPtr)
	s := Scanner {
		addr: *addrPtr,
		port: *portPtr,
		timeout: 10 * time.Second,
		numberOfThread: 1,
	}
	s.Run()
}

type Scanner struct {
	addr string
	port string
	timeout time.Duration
	numberOfThread int
}

func (s Scanner) Run() {
	conn, err := net.DialTimeout("tcp", s.addr+":"+s.port, s.timeout)
	if err != nil {
		fmt.Println("Dial failed: ", err)
		return
	}
	line := "" + conn.RemoteAddr().String() + " \t----- "
	conn.SetDeadline(time.Now().Add(s.timeout))
	c := tls.Client(conn, &tls.Config {
		InsecureSkipVerify: true,
		NextProtos: []string{"h2", "http/1.1"},
	})
	err = c.Handshake()
	if err != nil {
		fmt.Println("", line, "TLS handshake failed: ", err)
		return
	}
	defer c.Close()
	state := c.ConnectionState()
	fmt.Println("", line, "Found TLS v", TlsDic[state.Version], "\tALPN", state.NegotiatedProtocol, "\t", state.PeerCertificates[0].Subject)
}

var TlsDic = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}
