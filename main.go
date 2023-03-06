package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

func main() {
	addrPtr := flag.String("addr", "127.0.0.1", "Destination to start scan")
	portPtr := flag.String("port", "443", "Port to scan")
	threadPtr := flag.Int("thread", 2, "Number of threads to scan in parallel")
	flag.Parse()
	fmt.Println("Reality TLS Scanner running: ", *addrPtr, ":", *portPtr)
	s := Scanner {
		addr: *addrPtr,
		port: *portPtr,
		timeout: 10 * time.Second,
		numberOfThread: *threadPtr,
		mu: new(sync.Mutex),
	}
	s.Run()
}

type Scanner struct {
	addr           string
	port           string
	timeout        time.Duration
	numberOfThread int
	mu             *sync.Mutex
	high           net.IP
	low	           net.IP
}

func (s *Scanner) Run() {
	conn, err := net.DialTimeout("tcp", s.addr+":"+s.port, s.timeout)
	if err != nil {
		fmt.Println("Dial failed: ", err)
		return
	}
	line := "" + conn.RemoteAddr().String() + " \t----- "
	s.mu.Lock()
	s.high = conn.RemoteAddr().(*net.TCPAddr).IP
	s.low = conn.RemoteAddr().(*net.TCPAddr).IP
	s.mu.Unlock()
	conn.SetDeadline(time.Now().Add(s.timeout))
	c := tls.Client(conn, &tls.Config {
		InsecureSkipVerify: true,
		NextProtos: []string{"h2", "http/1.1"},
	})
	err = c.Handshake()
	if err != nil {
		fmt.Println("", line, "TLS handshake failed: ", err)
	} else {
		defer c.Close()
		state := c.ConnectionState()
		fmt.Println("", line, "Found TLS v", TlsDic[state.Version], "\tALPN", state.NegotiatedProtocol, "\t", state.PeerCertificates[0].Subject)
	}
	for i := 0; i < s.numberOfThread; i++ {
		go s.Scan(i % 2 == 0)
	}
	for {
		// now the scans are performed in goroutines
	}
}

func (s *Scanner) Scan(increment bool) {
	var addr string
	s.mu.Lock()
	if increment {
		s.high = nextIP(s.high, increment)
		addr = s.high.String()
	} else {
		s.low = nextIP(s.low, increment)
		addr = s.low.String()
	}
	s.mu.Unlock()
	conn, err := net.DialTimeout("tcp", addr+":"+s.port, s.timeout)
	if err != nil {
		fmt.Println("Dial failed: ", err)
	} else {
		line := "" + conn.RemoteAddr().String() + " \t----- "
		conn.SetDeadline(time.Now().Add(s.timeout))
		c := tls.Client(conn, &tls.Config {
			InsecureSkipVerify: true,
			NextProtos: []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			fmt.Println("", line, "TLS handshake failed: ", err)
		} else {
			defer c.Close()
			state := c.ConnectionState()
			fmt.Println("", line, "Found TLS v", TlsDic[state.Version], "\tALPN", state.NegotiatedProtocol, "\t", state.PeerCertificates[0].Subject)
		}
	}
	go s.Scan(increment)
}

func nextIP(ip net.IP, increment bool) net.IP {
    // Convert to big.Int and increment
    ipb := big.NewInt(0).SetBytes([]byte(ip))
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}

    // Add leading zeros
    b := ipb.Bytes()
    b = append(make([]byte, len(ip)-len(b)), b...)
    return net.IP(b)
}

var TlsDic = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}
