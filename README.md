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
# Note: infinity mode will be enabled automatically if `addr` is an IP or domain

# Scan a list of targets from a file (targets should be divided by line break):
./RealiTLScanner -in in.txt

# Crawl domains from a URL and scan:
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# Specify a port to scan, default: 443
./RealiTLScanner -addr 1.1.1.1 -port 443

# Specify the only TLS version in the output
./RealiTLScanner -addr 1.2.3.0/24 -tls 1.2

# Show verbose output, including failed scans and infeasible targets:
./RealiTLScanner -addr 1.2.3.0/24 -v

# Save results to a file, default: out.csv
./RealiTLScanner -addr www.microsoft.com -out file.csv

# Set a thread count, default: 1
./RealiTLScanner -addr wiki.ubuntu.com -thread 10

# Set a timeout for each scan, default: 10 (seconds)
./RealiTLScanner -addr 107.172.1.1/16 -timeout 5
```

### Enable Geo IP

To enable Geo IP information, place a MaxMind GeoLite2/GeoIP2 Country Database in the executing folder with the exact name `Country.mmdb`. You can download one from [here](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## Demo

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
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
202.70.64.2,ntc.net.np,*.ntc.net.np,"GlobalSign nv-sa",NP
196.200.160.70,mirror.marwan.ma,mirror.marwan.ma,"Let's Encrypt",MA
103.194.167.213,mirror.i3d.net,*.i3d.net,"Sectigo Limited",JP
194.127.172.131,nl.mirrors.clouvider.net,nl.mirrors.clouvider.net,"Let's Encrypt",NL
202.36.220.86,mirror.2degrees.nz,mirror.2degrees.nz,"Let's Encrypt",NZ
202.36.220.86,ubuntu.mirrors.theom.nz,mirror.2degrees.nz,"Let's Encrypt",NZ
158.37.28.65,ubuntu.hi.no,alma.hi.no,"Let's Encrypt",NO
193.136.164.6,ftp.rnl.tecnico.ulisboa.pt,ftp.rnl.ist.utl.pt,"Let's Encrypt",PT
75.2.60.5,cesium.di.uminho.pt,cesium.di.uminho.pt,"Let's Encrypt",US
195.14.50.21,mirror.corbina.net,ftp.corbina.net,"Let's Encrypt",RU
```

