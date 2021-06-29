package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	err, pki := create_self_signed_ca()
	if err == nil {
		err = dump_to_files(pki.CA.Subject.Organization[0], &pki)
	}
	if err != nil {
		log.Fatal(err)
	}
}

type PKI struct {
	CA   *x509.Certificate
	Priv crypto.PrivateKey
	Pub  crypto.PublicKey
	// DER encoded certificate
	Cert []byte
}

func create_self_signed_ca() (err error, pki PKI) {
	// (issuerDN + serialnumber) should be unique
	pki.CA = &x509.Certificate{
		SerialNumber: big.NewInt(1337),
		Subject: pkix.Name{
			Organization:  []string{"SpaceY"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 1, 0), // + 1 month
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, // not in spec, only windows CryptoAPI
		BasicConstraintsValid: true,                                    // results in MaxPathLen beeing interpreted as not beeing set
	}

	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return
	}
	pki.Priv = priv
	pki.Pub = priv.Public()

	// if parent == template -> self-signed
	parent := pki.CA
	template := pki.CA
	pki.Cert, err = x509.CreateCertificate(rand.Reader, parent, template, pki.Pub, pki.Priv)
	//^crt is the DER encoded certificate
	return
}

func dump_to_files(prefix string, pki *PKI) (err error) {
	fdcrt, err := os.Create(prefix + "-crt.pem")
	if err != nil {
		return
	}
	defer func() { err = fdcrt.Close() }()
	fdpkey, err := os.Create(prefix + "-pkey.pem")
	if err != nil {
		return
	}
	defer func() { err = fdpkey.Close() }()
	pem.Encode(fdcrt, &pem.Block{Type: "CERTIFICATE", Bytes: pki.Cert})
	pkey, err := x509.MarshalPKCS8PrivateKey(pki.Priv)
	if err != nil {
		return
	}
	pem.Encode(fdpkey, &pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: pkey})
	return
}
