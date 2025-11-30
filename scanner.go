package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

func GetTLSVersion(versionStr string) uint16 {
	versionStr = strings.TrimSpace(versionStr)
	switch versionStr {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	default:
		return 0 // no specific version targeted
	}
}

func ScanTLS(host Host, out chan<- string, geo *Geo) {
	if host.IP == nil {
		ip, err := LookupIP(host.Origin)
		if err != nil {
			slog.Debug("Failed to get IP from the origin", "origin", host.Origin, "err", err)
			return
		}
		host.IP = ip
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
	geoCode := geo.GetGeo(host.IP)

	targetVersion := GetTLSVersion(targetTLSVersion)
	versionMatch := true
	if targetVersion != 0 && targetVersion != state.Version {
	    // If a target is set, but it doesn't match the negotiated version, set match to false
		versionMatch = false
	}

	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 || !versionMatch {
		// not feasible
		log = slog.Debug
		feasible = false
	} else {
		out <- strings.Join([]string{host.IP.String(), host.Origin, domain, "\"" + issuers + "\"", geoCode}, ",") +
			"\n"
	}
	log("Connected to target", "feasible", feasible, "ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version), "alpn", alpn, "cert-domain", domain, "cert-issuer", issuers,
		"geo", geoCode)
}
