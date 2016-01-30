# Double Click TLS

## Usage

```
$ sudo make
docker run -i --rm -v `pwd`:/go/src/double-click-tls -w /go/src/double-click-tls golang:1.4-cross sh -c "go get && go get github.com/mitchellh/gox && gox -os='linux darwin windows' -arch='amd64 386' -output='bin/{{.Dir}}_{{.OS}}_{{.Arch}}'"
Number of parallel builds: 1

-->     linux/amd64: double-click-tls
-->       linux/386: double-click-tls
-->    darwin/amd64: double-click-tls
-->      darwin/386: double-click-tls
-->   windows/amd64: double-click-tls
-->     windows/386: double-click-tls
$ ls bin/
double-click-tls_darwin_386    double-click-tls_linux_386    double-click-tls_windows_386.exe
double-click-tls_darwin_amd64  double-click-tls_linux_amd64  double-click-tls_windows_amd64.exe
$ sudo ./bin/double-click-tls_linux_amd64
2016/01/30 15:14:41 reading account.key.pem
2016/01/30 15:14:41 open account.key.pem: no such file or directory
2016/01/30 15:14:44 writing account.key.pem
2016/01/30 15:14:44 new registration
Enter domain: asannou.keyword-on.net
2016/01/30 15:14:47 new authorization
2016/01/30 15:14:48 challenge ready
2016/01/30 15:14:48 listening :80
2016/01/30 15:14:51 create certificate request
2016/01/30 15:14:51 new certificate
2016/01/30 15:14:51 writing asannou.keyword-on.net.key.pem
2016/01/30 15:14:51 writing asannou.keyword-on.net.cert.pem
$ openssl x509 -text -in asannou.keyword-on.net.cert.pem -noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:75:48:fa:6a:85:7a:e2:46:91:03:6b:95:ca:8a:c1:75:8a
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X1
        Validity
            Not Before: Jan 30 14:15:00 2016 GMT
            Not After : Apr 29 14:15:00 2016 GMT
        Subject: CN=asannou.keyword-on.net
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
                Modulus:
                    00:da:48:32:3d:2d:36:bc:ee:93:9a:6f:5b:b8:ab:
                    b1:e4:80:dc:e7:42:74:66:db:36:54:f5:44:c0:fd:
                    c9:21:27:73:b5:2b:58:d9:6e:97:ed:ac:ad:b7:50:
                    de:7d:fa:61:bd:42:6d:cf:d3:9d:b6:19:62:ed:71:
                    30:d9:80:b8:50:64:76:50:16:08:19:b1:4f:19:f8:
                    2e:ee:ec:73:a1:ac:05:f4:6f:b5:3f:7e:e4:03:4f:
                    aa:63:dd:20:7a:2e:25:5e:e6:cb:50:a9:1a:bc:28:
                    b3:dc:ae:6d:28:85:d4:4a:66:c1:7e:5e:53:49:33:
                    40:0b:c6:4b:8f:c9:9e:76:f6:c3:76:86:a8:96:a5:
                    31:19:a5:9a:1d:61:d3:5e:3e:da:cc:b5:05:cc:a7:
                    b7:59:90:99:b3:ef:8d:63:32:0e:34:de:5c:a3:5e:
                    f8:33:89:63:60:69:58:72:d7:8c:88:62:1b:ce:e1:
                    c2:e1:ba:b0:6d:36:21:b8:ed:2e:d4:84:a6:c5:86:
                    a1:aa:5f:e1:d6:f0:26:f4:1b:28:39:dc:72:af:09:
                    66:be:59:6a:17:9d:95:5c:58:e6:14:ca:e2:e3:7c:
                    cc:5a:f8:c6:5f:dd:87:66:5f:f5:62:87:32:bb:c6:
                    5d:9f:dd:17:9a:62:a8:35:21:76:14:7b:c1:f9:f4:
                    92:eb:28:b5:af:ed:3c:a3:23:76:03:04:8d:d4:e3:
                    70:7f:1b:26:c5:58:6d:54:aa:1b:e7:90:b4:c7:61:
                    4c:be:73:7e:e8:67:b3:f4:e0:45:d0:2d:e9:1a:62:
                    2c:86:69:72:7b:d7:bd:44:0b:f3:9f:19:39:b5:d6:
                    60:7a:81:c7:bd:78:95:78:5f:f4:e1:4f:c1:43:46:
                    2d:54:38:c6:7f:76:2f:0a:26:ba:b9:88:9a:ef:f8:
                    4d:c8:03:d2:cd:9d:cf:13:47:ed:bb:a6:05:b0:81:
                    b4:f1:c2:bf:52:34:03:6d:85:f5:b9:a7:d1:eb:43:
                    11:2b:97:a7:52:cd:08:a9:a1:e0:de:72:bf:8a:3c:
                    8f:ad:6e:32:46:4f:98:77:4f:7e:b6:42:27:61:35:
                    7f:ce:6e:da:90:7f:3f:03:16:cd:63:be:3f:7a:87:
                    0c:4c:13:46:72:36:f9:45:73:8a:16:cb:e6:4c:40:
                    ea:d0:8d:45:0f:19:86:20:32:e9:b7:62:28:41:bc:
                    b6:0f:25:2a:49:4f:07:8f:10:13:19:32:49:07:95:
                    20:67:ed:de:de:fe:89:56:f7:3c:ef:70:a3:f0:b0:
                    ff:92:88:13:7f:78:e2:a8:28:67:49:d4:75:44:12:
                    57:b3:76:08:2f:f4:a1:46:0d:5e:43:1f:4a:7e:5a:
                    0b:0f:0d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            X509v3 Extended Key Usage:
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                78:9C:9F:1A:EE:29:6A:D9:B4:AF:85:4D:AD:71:5E:05:80:79:6F:07
            X509v3 Authority Key Identifier:
                keyid:A8:4A:6A:63:04:7D:DD:BA:E6:D1:39:B7:A6:45:65:EF:F3:A8:EC:A1

            Authority Information Access:
                OCSP - URI:http://ocsp.int-x1.letsencrypt.org/
                CA Issuers - URI:http://cert.int-x1.letsencrypt.org/

            X509v3 Subject Alternative Name:
                DNS:asannou.keyword-on.net
            X509v3 Certificate Policies:
                Policy: 2.23.140.1.2.1
                Policy: 1.3.6.1.4.1.44947.1.1.1
                  CPS: http://cps.letsencrypt.org
                  User Notice:
                    Explicit Text: This Certificate may only be relied upon by Relying Parties and only in accordance with the Certificate Policy found at https://letsencrypt.org/repository/

    Signature Algorithm: sha256WithRSAEncryption
         7f:fd:65:3f:6f:42:35:d5:7f:49:c8:2e:e5:d5:e1:86:0d:58:
         38:c3:45:b8:f8:bd:66:da:5a:1e:b7:35:54:a3:6a:1d:56:ba:
         c4:5b:e7:36:3c:58:7e:ca:72:ba:ec:6b:41:3d:25:b9:7b:1a:
         6a:0c:0c:a6:94:f2:b6:71:e0:e7:8a:1c:e7:e3:d1:e6:50:e7:
         a6:ca:d7:3b:ea:79:53:f3:28:69:3e:77:5d:46:b2:ff:07:df:
         46:0a:ca:cb:a7:9e:89:97:93:7b:d1:25:a3:e2:fe:44:d9:fb:
         2f:15:60:f3:43:0d:b3:66:44:66:f8:00:a7:92:30:60:dc:ee:
         e6:98:88:43:49:9f:06:fc:5a:db:55:64:50:ad:48:52:58:7d:
         a3:d4:28:b2:d0:ea:17:40:e7:75:74:b0:48:80:40:1c:f7:08:
         34:fb:9a:fb:55:72:e2:c9:ab:1c:c4:86:78:42:02:8d:87:60:
         c1:d3:50:e4:ee:db:b6:ea:8f:24:c1:05:76:85:99:9a:ef:03:
         21:49:03:4d:f7:39:8d:15:5b:b5:d6:1c:55:3f:37:d1:61:d2:
         8e:2b:ee:d7:c4:db:1b:28:b5:49:ac:50:45:fc:0a:88:03:f0:
         64:36:89:56:bf:96:b7:19:49:8c:b0:43:0e:14:10:67:0c:cf:
         a2:df:91:71
```
