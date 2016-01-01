package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"github.com/ericchiang/letsencrypt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

var directoryURL = "https://acme-v01.api.letsencrypt.org/directory"

var supportedChallenges = []string{
	letsencrypt.ChallengeHTTP,
	//letsencrypt.ChallengeTLSSNI,
}

func main() {
	cli, err := letsencrypt.NewClient(directoryURL)
	if err != nil {
		log.Fatal("failed to create client:", err)
	}
	accountKey, err := loadAccountKeyFile("accountkey.pem")
	if err != nil {
		accountKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			log.Fatal(err)
		}
		writeKeyFile("accountkey.pem", accountKey)
	}
	if _, err := cli.NewRegistration(accountKey); err != nil {
		log.Fatal("new registration failed:", err)
	}
	domain := os.Args[1]
	auth, _, err := cli.NewAuthorization(accountKey, "dns", domain)
	if err != nil {
		log.Fatal(err)
	}
	chals := auth.Combinations(supportedChallenges...)
	if len(chals) == 0 {
		log.Fatal("no supported challenge combinations")
	}
	chal := chals[0][0]
	listenHTTP(accountKey, chal)
	if err := cli.ChallengeReady(accountKey, chal); err != nil {
		log.Fatal(err)
	}
	csr, certKey, err := newCSR(domain)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := cli.NewCertificate(accountKey, csr)
	if err != nil {
		log.Fatal(err)
	}
	writeKeyFile("key.pem", certKey)
	writeCertificateFile("cert.pem", cert)
}

func loadAccountKeyFile(filename string) (*rsa.PrivateKey, error) {
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

func writePEM(filename string, perm os.FileMode, t string, b []byte) {
	data := pem.EncodeToMemory(&pem.Block{Type: t, Bytes: b})
	err := ioutil.WriteFile(filename, data, perm)
	if err != nil {
		log.Fatal(err)
	}
}

func writeKeyFile(filename string, key *rsa.PrivateKey) {
	writePEM(filename, 0400, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
}

func writeCertificateFile(filename string, cert *letsencrypt.CertificateResponse) {
	writePEM(filename, 0644, "CERTIFICATE", cert.Certificate.Raw)
}

func newCSR(domain string) (*x509.CertificateRequest, *rsa.PrivateKey, error) {
	certKey, err := rsa.GenerateKey(rand.Reader, 4096)
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

func listenHTTP(accountKey interface{}, chal letsencrypt.Challenge) {
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
		log.Fatal(http.ListenAndServe(":80", http.HandlerFunc(hf)))
	}()
}
