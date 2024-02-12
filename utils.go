package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

const (
	_ = iota
	HostTypeIP
	HostTypeCIDR
	HostTypeDomain
)

type HostType int

type Host struct {
	IP     net.IP
	Origin string
	Type   HostType
}

func Iterate(reader io.Reader) <-chan Host {
	scanner := bufio.NewScanner(reader)
	hostChan := make(chan Host)
	go func() {
		defer close(hostChan)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ip := net.ParseIP(line)
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				// ip address
				hostChan <- Host{
					IP:     ip,
					Origin: line,
					Type:   HostTypeIP,
				}
				continue
			}
			_, _, err := net.ParseCIDR(line)
			if err == nil {
				// ip cidr
				p, err := netip.ParsePrefix(line)
				if err != nil {
					slog.Warn("Invalid cidr", "cidr", line, "err", err)
				}
				if !p.Addr().Is4() && !enableIPv6 {
					continue
				}
				p = p.Masked()
				addr := p.Addr()
				for {
					if !p.Contains(addr) {
						break
					}
					ip = net.ParseIP(addr.String())
					if ip != nil {
						hostChan <- Host{
							IP:     ip,
							Origin: line,
							Type:   HostTypeCIDR,
						}
					}
					addr = addr.Next()
				}
				continue
			}
			if ValidateDomainName(line) {
				// domain
				hostChan <- Host{
					IP:     nil,
					Origin: line,
					Type:   HostTypeDomain,
				}
				continue
			}
			slog.Warn("Not a valid IP, IP CIDR or domain", "line", line)
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("Read file error", "err", err)
		}
	}()
	return hostChan
}
func ValidateDomainName(domain string) bool {
	r := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`)
	return r.MatchString(domain)
}
func ExistOnlyOne(arr []string) bool {
	exist := false
	for _, item := range arr {
		if item != "" {
			if exist {
				return false
			} else {
				exist = true
			}
		}
	}
	return exist
}
func IterateAddr(addr string) <-chan Host {
	hostChan := make(chan Host)
	_, _, err := net.ParseCIDR(addr)
	if err == nil {
		// is CIDR
		return Iterate(strings.NewReader(addr))
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		ip, err = LookupIP(addr)
		if err != nil {
			close(hostChan)
			slog.Error("Not a valid IP, IP CIDR or domain", "addr", addr)
			return hostChan
		}
	}
	go func() {
		slog.Info("Enable infinite mode", "init", ip.String())
		lowIP := ip
		highIP := ip
		hostChan <- Host{
			IP:     ip,
			Origin: addr,
			Type:   HostTypeIP,
		}
		for i := 0; i < math.MaxInt; i++ {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false)
				hostChan <- Host{
					IP:     lowIP,
					Origin: lowIP.String(),
					Type:   HostTypeIP,
				}
			} else {
				highIP = NextIP(highIP, true)
				hostChan <- Host{
					IP:     highIP,
					Origin: highIP.String(),
					Type:   HostTypeIP,
				}
			}
		}
	}()
	return hostChan
}
func LookupIP(addr string) (net.IP, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup: %w", err)
	}
	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil || enableIPv6 {
			arr = append(arr, ip)
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("no IP found")
	}
	return arr[0], nil
}
func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
func OutWriter(writer io.Writer) chan<- string {
	ch := make(chan string)
	go func() {
		for s := range ch {
			_, _ = io.WriteString(writer, s)
		}
	}()
	return ch
}
func NextIP(ip net.IP, increment bool) net.IP {
	// Convert to big.Int and increment
	ipb := big.NewInt(0).SetBytes(ip)
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}

	// Add leading zeros
	b := ipb.Bytes()
	b = append(make([]byte, len(ip)-len(b)), b...)
	return b
}
