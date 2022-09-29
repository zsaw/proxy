package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

func srvtls(certPEM, privPEM io.Reader) {
	conf := tls.Config{GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
		subCertPEM := bytes.NewBuffer(nil)
		subprivPEM := bytes.NewBuffer(nil)
		CreateSubCertificate(certPEM, privPEM, subCertPEM, subprivPEM, chi.ServerName)
		cert, err := tls.X509KeyPair(subCertPEM.Bytes(), subprivPEM.Bytes())
		return &cert, err
	}}
	l, err := tls.Listen("tcp", ":443", &conf)
	if err != nil {
		panic(err.Error())
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func(conn net.Conn) {
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				log.Println(err.Error())
				return
			}
			forward(req, conn)
		}(conn)
	}
}

func forwardtls(sconn net.Conn) {
	dconn, err := net.Dial("tcp", "127.0.0.1:443")
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer dconn.Close()
	resp := http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Status = "Connection Established"
	if err := resp.Write(sconn); err != nil {
		log.Println(err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func(sconn net.Conn, dconn net.Conn) {
		if _, err := io.Copy(dconn, sconn); err != nil {
			log.Println(err.Error())
		}
		wg.Done()
	}(sconn, dconn)
	go func(sconn net.Conn, dconn net.Conn) {
		if _, err := io.Copy(sconn, dconn); err != nil {
			log.Println(err.Error())
		}
		wg.Done()
	}(sconn, dconn)
	wg.Wait()
}

func forward(req *http.Request, sconn net.Conn) {
	addr := req.Host
	if _, _, err := net.SplitHostPort(req.Host); err != nil {
		addr = net.JoinHostPort(req.Host, "80")
	}
	dconn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Println(err.Error())
		return
	}
	defer dconn.Close()
	if err := req.Write(dconn); err != nil {
		log.Println(err.Error())
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(dconn), req)
	if err != nil {
		log.Println(err.Error())
		return
	}
	if err := resp.Write(sconn); err != nil {
		log.Println(err.Error())
		return
	}
}

type Config struct {
	CertPEM io.Reader
	PrivPEM io.Reader
}

func Serve(addr string, conf *Config, handler http.Handler) error {
	go srvtls(conf.CertPEM, conf.PrivPEM)

	l, err := net.Listen("tcp", ":8080")
	if err != nil {
		return err
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			req, err := http.ReadRequest(bufio.NewReader(conn))
			if err != nil {
				log.Println(err.Error())
				return
			}
			switch req.Method {
			case "CONNECT":
				forwardtls(conn)
			default:
				forward(req, conn)
			}
		}(conn)
	}
}
