package main

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
)

func Iterate(reader io.Reader) <-chan net.IP {
	scanner := bufio.NewScanner(reader)
	ipChan := make(chan net.IP)
	go func() {
		defer close(ipChan)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ip := net.ParseIP(line)
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				// ip address
				ipChan <- ip
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
						ipChan <- ip
					}
					addr = addr.Next()
				}
				continue
			}
			ips, err := net.LookupIP(line)
			if err == nil {
				// domain
				for _, ip = range ips {
					if ip.To4() != nil || enableIPv6 {
						ipChan <- ip
					}
				}
				continue
			}
			slog.Warn("Not a valid IP, IP CIDR or domain", "line", line)
		}
		if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("Read file error", "err", err)
		}
	}()
	return ipChan
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
