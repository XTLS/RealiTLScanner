package main

import (
	"crypto/tls"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	mu   *sync.Mutex
	high net.IP
	low  net.IP
}

func (s *Scanner) Scan(host Host, out chan<- string, increment bool) {
	if host.Infinity && host.IP != nil {
		s.mu.Lock()
		if s.high == nil {
			s.high = host.IP
			s.low = host.IP
			host.Origin = ""
			host.Type = HostTypeIP
		} else if increment {
			s.high = nextIP(s.high, increment)
			host.IP = s.high
		} else {
			s.low = nextIP(s.low, increment)
			host.IP = s.low
		}
		s.mu.Unlock()
	}
	ScanTLS(host, out, increment)
	if host.Infinity && host.IP != nil {
		go s.Scan(host, out, increment)
	}
}

func ScanTLS(host Host, out chan<- string, increment bool) {
	if host.IP == nil {
		ips, err := net.LookupIP(host.Origin)
		if err != nil {
			slog.Debug("Failed to lookup", "origin", host.Origin, "err", err)
			return
		}
		var arr []net.IP
		for _, ip := range ips {
			if ip.To4() != nil || enableIPv6 {
				arr = append(arr, ip)
			}
		}
		if len(arr) == 0 {
			slog.Debug("No IP found", "origin", host.Origin)
			return
		}
		host.IP = arr[0]
	}
	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", hostPort, time.Duration(timeout)*time.Second)
	if err != nil {
		slog.Debug("Cannot dial", "target", hostPort)
		return
	}
	defer conn.Close()
	err = conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
	if err != nil {
		slog.Error("Error setting deadline", "err", err)
		return
	}
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
	if host.Type == HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}
	c := tls.Client(conn, tlsCfg)
	err = c.Handshake()
	if err != nil {
		slog.Debug("TLS handshake failed", "target", hostPort)
		return
	}
	state := c.ConnectionState()
	alpn := state.NegotiatedProtocol
	domain := state.PeerCertificates[0].Subject.CommonName
	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	log := slog.Info
	feasible := true
	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		// not feasible
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{host.IP.String(), host.Origin, domain, "\"" + issuers + "\""}, ",") + "\n"
	}
	log("Connected to target", "feasible", feasible, "ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version), "alpn", alpn, "cert-domain", domain, "cert-issuer", issuers)
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
