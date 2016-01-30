package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ericchiang/letsencrypt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

const directoryURL = "https://acme-v01.api.letsencrypt.org/directory"
const keyBits = 4096
const ifconfigURL = "http://ifconfig.co"

var supportedChallenges = []string{
	letsencrypt.ChallengeHTTP,
	//letsencrypt.ChallengeTLSSNI,
}

func main() {
	cli, err := letsencrypt.NewClient(directoryURL)
	if err != nil {
		log.Fatal("failed to create client:", err)
	}
	accountKey, err := readKeyFile("account")
	if err != nil {
		accountKey, err = rsa.GenerateKey(rand.Reader, keyBits)
		if err != nil {
			log.Fatal(err)
		}
		writeKeyFile("account", accountKey)
	}
	log.Println("new registration")
	if _, err := cli.NewRegistration(accountKey); err != nil {
		log.Fatal("new registration failed:", err)
	}
	line := strings.Split(readLine("Enter domain: "), ":")
	domain := line[0]
	port := 80
	if domain == "" {
		domain = lookupDomain()
	}
	if len(line) > 1 {
		port, err = strconv.Atoi(line[1])
		if err != nil {
			log.Fatal(err)
		}
		if port > 1024 {
			log.Fatal("not privileged port")
		}
	}
	log.Println("new authorization")
	auth, _, err := cli.NewAuthorization(accountKey, "dns", domain)
	if err != nil {
		log.Fatal(err)
	}
	chals := auth.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		log.Fatal("no supported challenge combinations")
	}
	chal := chals[0][0]
	serveHTTP(accountKey, chal, port)
	log.Println("challenge ready")
	if err := cli.ChallengeReady(accountKey, chal); err != nil {
		log.Fatal(err)
	}
	csr, certKey, err := newCSR(domain)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("new certificate")
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		log.Fatal(err)
	}
	writeKeyFile(domain, certKey)
	writeCertificateFile(domain, cert)
}

func readLine(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func lookupDomain() string {
	req, _ := http.NewRequest("GET", ifconfigURL, nil)
	req.Header.Set("User-Agent", "curl/7.40.0")
	client := new(http.Client)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	addr := strings.TrimSpace(string(b))
	names, err := net.LookupAddr(addr)
	if err != nil {
		log.Fatal(err)
	}
	domain := strings.TrimRight(names[0], ".")
	log.Println("domain:", domain)
	return domain
}

func readKeyFile(name string) (*rsa.PrivateKey, error) {
	filename := fmt.Sprintf("%s.key.pem", name)
	log.Println("reading", filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("pem decode: no key found")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func writePEMFile(filename string, perm os.FileMode, t string, b []byte) {
	data := pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b})
	log.Println("writing", filename)
	err := ioutil.WriteFile(filename, data, perm)
	if err != nil {
		log.Fatal(err)
	}
}

func writeKeyFile(name string, key *rsa.PrivateKey) {
	filename := fmt.Sprintf("%s.key.pem", name)
	writePEMFile(filename, 0400, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
}

func writeCertificateFile(domain string, cert *letsencrypt.CertificateResponse) {
	filename := fmt.Sprintf("%s.cert.pem", domain)
	writePEMFile(filename, 0644, "CERTIFICATE", cert.Certificate.Raw)
}

func newCSR(domain string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &certKey.PublicKey,
		Subject:            pkix.Name{CommonName: domain},
		DNSNames:           []string{domain},
	}
	log.Println("create certificate request")
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, certKey)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, nil, err
	}
	return csr, certKey, nil
}

func serveHTTP(accountKey interface{}, chal letsencrypt.Challenge, port int) {
	if chal.Type != letsencrypt.ChallengeHTTP {
		log.Fatal("this isn't an HTTP challenge!")
	}
	path, resource, err := chal.HTTP(accountKey)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		hf := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			io.WriteString(w, resource)
		}
		addr := fmt.Sprintf(":%d", port)
		log.Println("listening", addr)
		log.Fatal(http.ListenAndServe(addr, http.HandlerFunc(hf)))
	}()
}
