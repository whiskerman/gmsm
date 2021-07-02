package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/whiskerman/gmsm/sm2"
	"github.com/whiskerman/gmsm/x509"
)

func main() {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	log.Printf(" priv :%v\n", priv)
	if err != nil {
		log.Fatal(err)
	}

	privPem, err := x509.WriteSM2PrivateKeyToPem(priv, nil) // 生成密钥文件
	log.Printf("privPem :%s\n", privPem)
	if err != nil {
		log.Fatal(err)
	}
	priv1, _ := x509.ReadSM2PrivateKeyFromPem(privPem, nil)
	log.Printf("priv1:%v", priv1)
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	pubkeyPem, _ := x509.WritePublicKeyToPem(pubKey)            // 生成公钥文件
	privKey, err := x509.ReadSM2PrivateKeyFromPem(privPem, nil) // 读取密钥
	log.Println("--------1---------")
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err = x509.ReadPublicKeyFromPem(pubkeyPem) // 读取公钥
	if err != nil {
		log.Fatal(err)
	}
	log.Println("--------2---------")
	templateReq := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test"},
		},
		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: x509.SM2WithSM3,
	}
	log.Println("--------3---------")
	reqPem, err := x509.CreateCertificateRequestToPem(&templateReq, privKey)
	if err != nil {
		log.Fatal(err)
	}
	req, err := x509.ReadCertificateRequestFromPem(reqPem)
	if err != nil {
		log.Fatal(err)
	}
	err = req.CheckSignature()
	if err != nil {
		log.Fatalf("Request CheckSignature error:%v", err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
	log.Println("--------4---------")
	testExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	testUnknownExtKeyUsage := []asn1.ObjectIdentifier{[]int{1, 2, 3}, []int{2, 59, 1}}
	extraExtensionData := []byte("extra extension")
	commonName := "test.example.com"
	template := x509.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: x509.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		ExtKeyUsage:        testExtKeyUsage,
		UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: extraExtensionData,
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	pubKey, _ = priv.Public().(*sm2.PublicKey)
	certpem, err := x509.CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		log.Fatal("failed to create cert file")
	}
	cert, err := x509.ReadCertificateFromPem(certpem)
	if err != nil {
		log.Fatal("failed to read cert file")
	}
	err = cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
	if err != nil {
		log.Fatal(err)
	} else {
		fmt.Printf("CheckSignature ok\n")
	}
}
