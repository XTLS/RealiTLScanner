package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

var TLSDictionary = map[uint16]string{
	0x0301: "1.0",
	0x0302: "1.1",
	0x0303: "1.2",
	0x0304: "1.3",
}

func ScanTLS(ip net.IP, out chan<- string) {
	hostPort := net.JoinHostPort(ip.String(), strconv.Itoa(port))
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
	c := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	})
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
	if state.Version != 0x0304 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		// not feasible
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{ip.String(), domain, "\"" + issuers + "\""}, ",") + "\n"
	}
	log("Connected to target", "feasible", feasible, "host", ip.String(),
		"tls", TLSDictionary[state.Version],
		"alpn", alpn, "domain", domain, "issuer", issuers)
}
