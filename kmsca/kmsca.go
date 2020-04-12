package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/glassechidna/go-kms-signer/kmssigner"
	"io/ioutil"
	"math/big"
	"os"
	"time"
)

var defaultRootCAKmsAlias = "alias/kmsca-rootx"
var rootPemPath = "root.pem"
var csrPath = "csr.pem"
var csrKeyPath = "csr.key"
var certPath = "cert.pem"

var kmsApi kmsiface.KMSAPI

func main() {
	sess, err := session.NewSessionWithOptions(session.Options{SharedConfigState: session.SharedConfigEnable})
	if err != nil {
		panic(err)
	}
	kmsApi = kms.New(sess)

	if len(os.Args) == 1 {
		usage()
	}

	switch os.Args[1] {
	case "mk-csr":
		makeCertificateRequest(os.Args[2:])
	case "sign-csr":
		signCertificateRequest()
	case "mk-root":
		makeRootCA()
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `
Usage: 
	kmsca mk-csr example.com www.example.com [domain...]
	kmsca sign-csr
	kmsca mk-root`)
	os.Exit(1)
}

func makeCertificateRequest(dnsNames []string) {
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: dnsNames[0]},
		DNSNames: dnsNames,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, certPrivKey)
	if err != nil {
		panic(err)
	}

	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	err = ioutil.WriteFile(csrPath, body, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote CSR request to %s\n", csrPath)

	body = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey)})
	err = ioutil.WriteFile(csrKeyPath, body, 0600)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote CSR private key to %s\n", csrKeyPath)
}

func signCertificateRequest() {
	csrBytes, err := ioutil.ReadFile(csrPath)
	if err != nil {
		panic(err)
	}

	csrPem, _ := pem.Decode(csrBytes)
	csr, err := x509.ParseCertificateRequest(csrPem.Bytes)
	if err != nil {
		panic(err)
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(20191),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	parentBytes, err := ioutil.ReadFile(rootPemPath)
	if err != nil {
		panic(err)
	}

	parentPem, _ := pem.Decode(parentBytes)
	parent, err := x509.ParseCertificate(parentPem.Bytes)
	if err != nil {
		panic(err)
	}

	signer := kmssigner.New(kmsApi, defaultRootCAKmsAlias, kmssigner.ModeRsaPkcs1v15)
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parent, csr.PublicKey, signer)
	if err != nil {
		panic(err)
	}

	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	err = ioutil.WriteFile(certPath, body, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote leaf certificate to %s\n", certPath)
}

func makeRootCA() {
	created, err := kmsApi.CreateKey(&kms.CreateKeyInput{
		CustomerMasterKeySpec: aws.String(kms.CustomerMasterKeySpecRsa2048),
		KeyUsage:              aws.String(kms.KeyUsageTypeSignVerify),
		Description:           &defaultRootCAKmsAlias,
		Tags: []*kms.Tag{
			{
				TagKey:   aws.String("created-by"),
				TagValue: aws.String("kmsca"),
			},
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created KMS key with ID %s\n", *created.KeyMetadata.KeyId)

	_, err = kmsApi.CreateAlias(&kms.CreateAliasInput{
		AliasName:   &defaultRootCAKmsAlias,
		TargetKeyId: created.KeyMetadata.KeyId,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Created KMS key alias named %s\n", defaultRootCAKmsAlias)

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2020),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	signer := kmssigner.New(kmsApi, defaultRootCAKmsAlias, kmssigner.ModeRsaPkcs1v15)
	pub, err := signer.RetrievePublicKey()
	if err != nil {
		panic(err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, signer)
	if err != nil {
		panic(err)
	}

	body := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	err = ioutil.WriteFile(rootPemPath, body, 0600)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote root CA certificate to %s\n", rootPemPath)
}

