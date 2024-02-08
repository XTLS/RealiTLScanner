# Reality - TLS - Scanner

## Building

Requirement: Go 1.21+

```bash
go build
```

## Usage

It is recommended to run this tool locally, as running the scanner in the cloud may cause the VPS to be flagged.
```bash
# Show help
./RealiTLScanner

# Scan a specific IP, IP CIDR or domain:
./RealiTLScanner -addr 1.2.3.4

# Scan a list of targets from a file (targets should be divided by line break):
./RealiTLScanner -in in.txt

# Crawl domains from a URL and scan:
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# Specify a port to scan, default: 443
./RealiTLScanner -addr 1.1.1.1 -port 443

# Show verbose output, including failed scans and infeasible targets:
./RealiTLScanner -addr 1.2.3.0/24 -v

# Save results to a file, default: out.csv
./RealiTLScanner -addr www.microsoft.com -out file.csv

# Set a thread count, default: 1
./RealiTLScanner -addr wiki.ubuntu.com -thread 10

# Set a timeout for each scan, default: 10 (seconds)
./RealiTLScanner -addr 107.172.1.1/16 -timeout 5
```

Example stdout:
```bash
2024/02/08 20:51:10 INFO Started all scanning threads time=2024-02-08T20:51:10.017+08:00
2024/02/08 20:51:10 INFO Connected to target feasible=true host=107.172.103.9 tls=1.3 alpn=h2 domain=rocky-linux.tk issuer="Let's Encrypt"
2024/02/08 20:51:10 INFO Connected to target feasible=true host=107.172.103.11 tls=1.3 alpn=h2 domain=rn.allinai.dev issuer="Let's Encrypt"
2024/02/08 20:51:13 INFO Connected to target feasible=true host=107.172.103.16 tls=1.3 alpn=h2 domain=san.hiddify01.foshou.vip issuer="Let's Encrypt"
2024/02/08 20:51:13 INFO Connected to target feasible=true host=107.172.103.19 tls=1.3 alpn=h2 domain=mgzx19.cnscholar.top issuer="Let's Encrypt"
2024/02/08 20:51:13 INFO Connected to target feasible=true host=107.172.103.22 tls=1.3 alpn=h2 domain=hy2.znull.top issuer=ZeroSSL
2024/02/08 20:51:21 INFO Connected to target feasible=true host=107.172.103.37 tls=1.3 alpn=h2 domain=c1.webgenbd.com issuer="Let's Encrypt"
2024/02/08 20:51:23 INFO Connected to target feasible=true host=107.172.103.46 tls=1.3 alpn=h2 domain=racknerd.myideal.xyz issuer="Let's Encrypt"
2024/02/08 20:51:38 INFO Scanning completed time=2024-02-08T20:51:38.988+08:00 elapsed=28.97043s
```

Example output file:

```csv
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER
52.140.219.235,www.cherryservers.com,*.cherryservers.com,"GlobalSign nv-sa"
172.66.40.234,veesp.com,veesp.com,"Cloudflare, Inc."
172.66.43.22,veesp.com,veesp.com,"Cloudflare, Inc."
193.1.193.205,www.heanet.ie,www.heanet.ie,"GEANT Vereniging"
185.242.104.18,mirror.veesp.com,mirror.veesp.com,"Let's Encrypt"
79.98.24.240,www.serveriai.lt,*.serveriai.lt,"Sectigo Limited"
91.211.244.3,www.vpsnet.com,*.vpsnet.com,"Sectigo Limited"
31.131.0.101,www.ihost.md,ihost.md,"Sectigo Limited"
194.127.172.131,nl.mirrors.clouvider.net,nl.mirrors.clouvider.net,"Let's Encrypt"
31.131.0.222,mirror.ihost.md,mirror.ihost.md,"Let's Encrypt"
```

