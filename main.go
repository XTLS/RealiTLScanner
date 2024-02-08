package main

import (
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var addr string
var in string
var port int
var thread int
var out string
var timeout int
var verbose bool
var enableIPv6 bool

func main() {
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")
	flag.StringVar(&addr, "addr", "", "specify an IP, IP CIDR or domain to scan")
	flag.StringVar(&in, "in", "", "specify a file that contains multiple "+
		"IPs, IP CIDRs or domains to scan, divided by line break")
	flag.IntVar(&port, "port", 443, "specify a HTTPS port to check")
	flag.IntVar(&thread, "thread", 1, "count of concurrent tasks")
	flag.StringVar(&out, "out", "out.csv", "output file to store the result")
	flag.IntVar(&timeout, "timeout", 10, "timeout for every check")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.BoolVar(&enableIPv6, "46", false, "Enable IPv6 in additional to IPv4")
	flag.Parse()
	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}
	if addr != "" && in != "" ||
		addr == "" && in == "" {
		slog.Error("You must specify either `addr` or `in`")
		flag.PrintDefaults()
		return
	}
	outWriter := io.Discard
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			slog.Error("Error opening file", "path", out)
			return
		}
		defer f.Close()
		_, _ = f.WriteString("IP,DOMAIN,CERTIFICATE\n")
		outWriter = f
	}
	var ipChan <-chan net.IP
	if addr != "" {
		ipChan = Iterate(strings.NewReader(addr))
	} else {
		f, err := os.Open(in)
		if err != nil {
			slog.Error("Error reading file", "path", in)
			return
		}
		defer f.Close()
		ipChan = Iterate(f)
	}
	var wg sync.WaitGroup
	wg.Add(thread)
	for i := 0; i < thread; i++ {
		go func() {
			for ip := range ipChan {
				ScanTLS(ip, outWriter)
			}
			wg.Done()
		}()
	}
	t := time.Now()
	slog.Info("Started all scanning threads", "time", t)
	wg.Wait()
	slog.Info("Scanning completed", "time", time.Now(), "elapsed", time.Since(t).String())
}
