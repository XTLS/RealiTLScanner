package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

func ScanTLS(host Host, out chan<- string) {
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
