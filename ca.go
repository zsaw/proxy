package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"time"
)

func GenerateRandomKey(length int) []byte {
	k := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil
	}
	return k
}

func CreateRootCertificate(certPEM, privPEM io.Writer) error {
	keyID := GenerateRandomKey(20)
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(int64(binary.BigEndian.Uint64(GenerateRandomKey(16)))),
		Subject: pkix.Name{
			Organization: []string{"Proxy Inc"},
			CommonName:   "Proxy Global Root CA",
		},
		SubjectKeyId:          keyID,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		AuthorityKeyId:        keyID,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, cert, &privKey.PublicKey, privKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return err
	}

	if err := pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}); err != nil {
		return err
	}

	return nil
}

func CreateSubCertificate(parentCertPEM, parentPrivPEM []byte, certPEM, privPEM io.Writer, servername string) error {
	pemToBytes := func(data []byte) []byte {
		p, _ := pem.Decode(data)
		return p.Bytes
	}

	parentCert, err := x509.ParseCertificate(pemToBytes(parentCertPEM))
	if err != nil {
		return err
	}

	parenPrivKey, err := x509.ParsePKCS1PrivateKey(pemToBytes(parentPrivPEM))
	if err != nil {
		return err
	}

	cert := &x509.Certificate{
		SerialNumber:          big.NewInt(1658),
		Subject:               pkix.Name{CommonName: servername},
		DNSNames:              []string{servername},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		AuthorityKeyId:        parentCert.SubjectKeyId,
		IsCA:                  false,
		BasicConstraintsValid: false,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, parentCert, &privKey.PublicKey, parenPrivKey)
	if err != nil {
		return err
	}

	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return err
	}

	return pem.Encode(privPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})
}
