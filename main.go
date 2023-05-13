package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

func main() {
	addrPtr := flag.String("addr", "127.0.0.1", "Destination to start scan")
	portPtr := flag.String("port", "443", "Port to scan")
	threadPtr := flag.Int("thread", 2, "Number of threads to scan in parallel")
	outPutFile := flag.Bool("o", false, "Is output to results.txt")
	timeOutPtr := flag.Int("timeOut", 10, "Time out of a scan")
	showFailPtr := flag.Bool("showFail", false, "Is Show fail logs")
	flag.Parse()
	s := Scanner{
		addr:           *addrPtr,
		port:           *portPtr,
		showFail:       *showFailPtr,
		output:         *outPutFile,
		timeout:        time.Duration(*timeOutPtr) * time.Second,
		numberOfThread: *threadPtr,
		mu:             new(sync.Mutex),
	}
	if *outPutFile {
		s.logFile, _ = os.OpenFile("results.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	}
	s.Print(fmt.Sprint("Reality TLS Scanner running: ", *addrPtr, ":", *portPtr, " start scan at : ", time.Now().Format(time.RFC3339)))
	defer s.logFile.Close()
	s.Run()
}

type Scanner struct {
	addr           string
	port           string
	output         bool
	showFail       bool
	logFile        *os.File
	timeout        time.Duration
	numberOfThread int
	mu             *sync.Mutex
	high           net.IP
	low            net.IP
}

func (s *Scanner) Run() {
	str := s.addr
	addr := net.ParseIP(s.addr)
	if addr != nil && addr.To4() == nil {
		str = "[" + addr.String() + "]"
	}
	conn, err := net.DialTimeout("tcp", str+":"+s.port, s.timeout)
	if err != nil {
		s.Print(fmt.Sprint("Dial failed: ", err))
	} else {
		addr = conn.RemoteAddr().(*net.TCPAddr).IP
		line := "" + conn.RemoteAddr().String() + " \t"
		conn.SetDeadline(time.Now().Add(s.timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			s.Print(fmt.Sprint("", line, "TLS handshake failed: ", err))
		} else {
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			if alpn == "" {
				alpn = "  "
			}
			s.Print(fmt.Sprint("", line, "----- Found TLS v", TlsDic[state.Version], "\tALPN ", alpn, "\t", state.PeerCertificates[0].Subject))
			c.Close()
		}
	}
	if addr == nil {
		s.Print("Invalid address format")
		return
	}

	s.mu.Lock()
	s.high = addr
	s.low = addr
	s.mu.Unlock()
	for i := 0; i < s.numberOfThread; i++ {
		go s.Scan(i%2 == 0)
	}
	for {
		// now the scans are performed in goroutines
	}
}

func (s *Scanner) Scan(increment bool) {
	var addr net.IP
	s.mu.Lock()
	if increment {
		s.high = nextIP(s.high, increment)
		addr = s.high
	} else {
		s.low = nextIP(s.low, increment)
		addr = s.low
	}
	s.mu.Unlock()
	str := addr.String()
	if addr.To4() == nil {
		str = "[" + str + "]"
	}
	conn, err := net.DialTimeout("tcp", str+":"+s.port, s.timeout)
	if err != nil {
		if s.showFail {
			s.Print(fmt.Sprint("Dial failed: ", err))
		}
	} else {
		line := "" + conn.RemoteAddr().String() + " \t"
		conn.SetDeadline(time.Now().Add(s.timeout))
		c := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		err = c.Handshake()
		if err != nil {
			if s.showFail {
				s.Print(fmt.Sprint("", line, "TLS handshake failed: ", err))
			}
		} else {
			defer c.Close()
			state := c.ConnectionState()
			alpn := state.NegotiatedProtocol
			if alpn == "" {
				alpn = "  "
			}
			if s.showFail || (state.Version == 0x0304 && alpn == "h2") {
				s.Print(fmt.Sprint("", line, "----- Found TLS v", TlsDic[state.Version], "\tALPN ", alpn, "\t", state.PeerCertificates[0].Subject))
			}
		}
	}
	go s.Scan(increment)
}

func (s *Scanner) Print(outStr string) {
	if s.output {
		s.logFile.WriteString(outStr + "\n")
	}
	fmt.Println(outStr)
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
