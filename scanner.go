package main

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// dnsCache stores only successful resolutions.
var dnsCache = make(map[string][]net.IP)
var dnsCacheMu sync.RWMutex
var dnsSF singleflight.Group


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
		CurvePreferences:   []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
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
	domain := ""
	if len(state.PeerCertificates[0].DNSNames) > 0 {
		domain = state.PeerCertificates[0].DNSNames[0]
	} else {
		domain = state.PeerCertificates[0].Subject.CommonName
	}

	issuers := strings.Join(state.PeerCertificates[0].Issuer.Organization, " | ")
	length := 0
	leaf := state.PeerCertificates[0]
	for _, cert := range state.PeerCertificates {
		length += len(cert.Raw)
		if len(cert.DNSNames) != 0 {
			leaf = cert
		}
	}

	feasible := true
	geoCode := geo.GetGeo(host.IP)
	if state.Version != tls.VersionTLS13 || alpn != "h2" || len(domain) == 0 || len(issuers) == 0 {
		// not feasible
		feasible = false
	}

	if feasible && resolveDomains {
		lookupDomain := domain
		if strings.HasPrefix(lookupDomain, "*.") {
			lookupDomain = lookupDomain[2:]
		}

		dnsCacheMu.RLock()
		resolvedIPs, cached := dnsCache[lookupDomain]
		dnsCacheMu.RUnlock()

		if !cached {
			v, err, _ := dnsSF.Do(lookupDomain, func() (interface{}, error) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
				defer cancel()
				addrs, err := net.DefaultResolver.LookupIPAddr(ctx, lookupDomain)
				if err != nil {
					return ([]net.IP)(nil), err
				}
				ips := make([]net.IP, len(addrs))
				for i, a := range addrs {
					ips[i] = a.IP
				}
				dnsCacheMu.Lock()
				dnsCache[lookupDomain] = ips
				dnsCacheMu.Unlock()
				return ips, nil
			})
			if err != nil {
				slog.Debug("DNS resolution failed", "domain", lookupDomain, "err", err)
				resolvedIPs = nil
			} else {
				resolvedIPs = v.([]net.IP)
			}
		}

		ipMatched := false
		for _, rip := range resolvedIPs {
			if rip.Equal(host.IP) {
				ipMatched = true
				break
			}
		}
		if !ipMatched {
			slog.Debug("IP mismatch with cert domain DNS records", "ip", host.IP.String(), "domain", lookupDomain)
			feasible = false
		}
	}

	log := slog.Info
	if !feasible {
		log = slog.Debug
	} else {
		out <- strings.Join([]string{
			host.IP.String(), 
			host.Origin, 
			tls.VersionName(state.Version), 
			alpn,
			state.CurveID.String(),
			strconv.Itoa(length) + "(certs count: " + strconv.Itoa(len(state.PeerCertificates)) + ")",
			leaf.SignatureAlgorithm.String(),
			leaf.PublicKeyAlgorithm.String(),
			domain, 
			"\"" + issuers + "\"", 
			geoCode}, ",") + "\n"
	}
	log("Connected to target", "feasible", feasible, 
		"ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version), 
		"alpn", alpn, 
		"curve", state.CurveID.String(),
		"cert-length", strconv.Itoa(length) + "(certs count: " + strconv.Itoa(len(state.PeerCertificates)) + ")",
		"cert-signature", leaf.SignatureAlgorithm.String(),
		"cert-publickey", leaf.PublicKeyAlgorithm.String(),
		"cert-domain", domain, 
		"cert-issuer", issuers,
		"geo", geoCode)
}
