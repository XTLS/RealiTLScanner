package main

import (
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
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
var url string

func main() {
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")
	flag.StringVar(&addr, "addr", "", "Specify an IP, IP CIDR or domain to scan")
	flag.StringVar(&in, "in", "", "Specify a file that contains multiple "+
		"IPs, IP CIDRs or domains to scan, divided by line break")
	flag.IntVar(&port, "port", 443, "Specify a HTTPS port to check")
	flag.IntVar(&thread, "thread", 2, "Count of concurrent tasks")
	flag.StringVar(&out, "out", "out.csv", "Output file to store the result")
	flag.IntVar(&timeout, "timeout", 10, "Timeout for every check")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&enableIPv6, "46", false, "Enable IPv6 in additional to IPv4")
	flag.StringVar(&url, "url", "", "Crawl the domain list from a URL, "+
		"e.g. https://launchpad.net/ubuntu/+archivemirrors")
	flag.Parse()
	s := Scanner{
		mu: new(sync.Mutex),
	}

	if verbose {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})))
	} else {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})))
	}
	if !ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("You must specify and only specify one of `addr`, `in`, or `url`")
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
		_, _ = f.WriteString("IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER\n")
		outWriter = f
	}
	var hostChan <-chan Host
	if addr != "" {
		hostChan = Iterate(strings.NewReader(addr), true)
	} else if in != "" {
		f, err := os.Open(in)
		if err != nil {
			slog.Error("Error reading file", "path", in)
			return
		}
		defer f.Close()
		hostChan = Iterate(f, false)
	} else {
		slog.Info("Fetching url...")
		resp, err := http.Get(url)
		if err != nil {
			slog.Error("Error fetching url", "err", err)
			return
		}
		defer resp.Body.Close()
		v, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("Error reading body", "err", err)
			return
		}
		arr := regexp.MustCompile("(http|https)://(.*?)[/\"<>\\s]+").FindAllStringSubmatch(string(v), -1)
		var domains []string
		for _, m := range arr {
			domains = append(domains, m[2])
		}
		domains = RemoveDuplicateStr(domains)
		slog.Info("Parsed domains", "count", len(domains))
		hostChan = Iterate(strings.NewReader(strings.Join(domains, "\n")), len(domains) <= 1)
	}
	outCh := OutWriter(outWriter)
	defer close(outCh)
	var wg sync.WaitGroup
	wg.Add(thread)
	for i := 0; i < thread; i++ {
		go func() {
			for ip := range hostChan {
				ip = s.Scan(ip, outCh, true)
				if ip.Infinity { // only one ip
					for i := 0; i < thread - 1; i++ {
						go s.Scan(ip, outCh, i%2 == 1)
					}
					for {}
				}
			}
			wg.Done()
		}()
	}
	t := time.Now()
	slog.Info("Started all scanning threads", "time", t)
	wg.Wait()
	slog.Info("Scanning completed", "time", time.Now(), "elapsed", time.Since(t).String())
}
