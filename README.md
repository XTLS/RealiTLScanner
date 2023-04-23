# Reality - TLS - Scanner

Build
```
go build
```

Usage

Recommend to run this tool locally. It may cause VPS to be flagged if you run scanner in the cloud.
```
./RealiTLScanner -addr www.microsoft.com -showFail -o
./RealiTLScanner -addr 20.53.203.50 -showFail -o
./RealiTLScanner -addr 2607:f8b0:4004:c1b::65 -thread 10 -showFail -o
```

Example
```
Reality TLS Scanner running:  20.53.203.50 : 443
 20.53.203.50:443       -----  Found TLS v 1.3  ALPN h2          CN=*.oneroute.microsoft.com,O=Microsoft Corporation,L=Redmond,ST=WA,C=US
 20.53.203.48:443       TLS handshake failed:  read tcp 192.168.211.138:37858->20.53.203.48:443: read: connection reset by peer
 20.53.203.46:443       -----  Found TLS v 1.3  ALPN h2          CN=apiserver
 20.53.203.45:443       -----  Found TLS v 1.2  ALPN http/1.1    CN=*.canon.com.au,O=Canon Australia Pty. Ltd.,L=Macquarie Park,ST=New South Wales,C=AU
 20.53.203.43:443       -----  Found TLS v 1.2  ALPN             CN=bst-c0a0be99-3539-4442-8884-161054d9aba3.bastion.azure.com,O=Microsoft Corporation,L=Redmond,ST=WA,C=US
Dial failed:  dial tcp 20.53.203.52:443: i/o timeout
```
