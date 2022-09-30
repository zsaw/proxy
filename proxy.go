package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"
)

type OnRequestFunc func(req *http.Request) (*http.Request, *http.Response)

type OnResponseFunc func(resp *http.Response) *http.Response

func defaultOnRequestFunc(req *http.Request) (*http.Request, *http.Response) { return req, nil }

func defaultOnResponseFunc(resp *http.Response) *http.Response { return resp }

func NewServer() Server {
	srv := Server{
		Logger:         *logrus.New(),
		onRequestFunc:  defaultOnRequestFunc,
		onResponseFunc: defaultOnResponseFunc,
	}
	return srv
}

type Server struct {
	Addr           string
	Logger         logrus.Logger
	listen         net.Listener
	enTlsTunnel    bool
	certPEM        []byte
	privPEM        []byte
	certificates   map[string]*tls.Certificate
	onRequestFunc  OnRequestFunc
	onResponseFunc OnResponseFunc
}

func (srv *Server) ListenAndServe() error {
	srv.enTlsTunnel = true

	addr := srv.Addr
	if addr == "" {
		addr = ":8080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return srv.Serve(ln)
}

func (srv *Server) ListenAndServeTLS(certPEM, privPEM []byte) error {
	srv.certPEM = certPEM
	srv.privPEM = privPEM

	addr := srv.Addr
	if addr == "" {
		addr = ":8080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	return srv.Serve(ln)
}

func (srv *Server) Serve(l net.Listener) error {
	srv.listen = l

	for {
		conn, err := srv.listen.Accept()
		if err != nil {
			srv.Logger.Error(err)
			return err
		}
		go srv.newConn(conn)
	}
}

func (srv *Server) OnRequest(fn OnRequestFunc) { srv.onRequestFunc = fn }

func (srv *Server) OnResponse(fn OnResponseFunc) { srv.onResponseFunc = fn }

func (srv *Server) newConn(conn net.Conn) {
	defer conn.Close()

	var err error
	var req *http.Request

	// Read Request
	req, err = http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		srv.Logger.Error(err)
		return
	}

	switch req.Method {
	case "CONNECT":
		switch srv.enTlsTunnel {
		case true:
			err = srv.tlsTunnel(conn, req)
			if err != nil {
				srv.Logger.Error(err)
				return
			}
		case false:
			err = srv.tlsConn(conn)
			if err != nil {
				srv.Logger.Error(err)
				return
			}
		}
	default:
		err = srv.forwardHttp(conn, req)
		if err != nil {
			srv.Logger.Error(err.Error())
			return
		}
	}
}

func (srv *Server) tlsTunnel(sconn net.Conn, req *http.Request) error {
	var err error
	var dconn net.Conn
	var resp *http.Response
	var wg sync.WaitGroup

	wg.Add(2)

	// Dial the destination server
	dconn, err = net.Dial("tcp", req.Host)
	if err != nil {
		return err
	}
	defer dconn.Close()

	// Send the "Connection Established" message to the source Connection
	resp = &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Status = "Connection Established"
	if err := resp.Write(sconn); err != nil {
		return err
	}

	go func() {
		_, err = io.Copy(dconn, sconn)
		if err != nil {
			srv.Logger.Error(err.Error())
		}
		wg.Done()
	}()
	go func() {
		_, err = io.Copy(sconn, dconn)
		if err != nil {
			srv.Logger.Error(err.Error())
		}
		wg.Done()
	}()
	wg.Wait()
	return nil
}

func (srv *Server) tlsConn(sconn net.Conn) error {
	var err error
	var dconn net.Conn
	var addr string
	var req *http.Request

	// Send the "Connection Established" message to the source Connection
	resp := &http.Response{
		ProtoMajor: 1,
		ProtoMinor: 1,
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
	}
	resp.Status = "Connection Established"
	if err := resp.Write(sconn); err != nil {
		return err
	}

	// Perform tls handshake with the source Connection
	sconn = tls.Server(sconn, &tls.Config{GetCertificate: srv.getCertificate})

	req, err = http.ReadRequest(bufio.NewReader(sconn))
	if err != nil {
		return err
	}

	req, resp = srv.onRequestFunc(req)
	switch resp {
	case nil:
		// Dial the destination server
		addr = req.Host
		_, _, err = net.SplitHostPort(addr)
		if err != nil {
			addr = net.JoinHostPort(addr, "443")
		}
		dconn, err = tls.Dial("tcp", addr, &tls.Config{})
		if err != nil {
			return err
		}

		// Send request to destination server
		err = req.Write(dconn)
		if err != nil {
			return err
		}

		// Read the response of the destination server
		resp, err = http.ReadResponse(bufio.NewReader(dconn), req)
		if err != nil {
			return err
		}

		// Send response to source address
		resp = srv.onResponseFunc(resp)
		return resp.Write(sconn)
	default:
		// Send response to source address
		return resp.Write(sconn)
	}
}

func (srv *Server) forwardHttp(sconn net.Conn, req *http.Request) error {
	var err error
	var addr string
	var dconn net.Conn
	var resp *http.Response

	req, resp = srv.onRequestFunc(req)

	switch resp {
	case nil:
		// Dial the destination server
		addr = req.Host
		_, _, err = net.SplitHostPort(addr)
		if err != nil {
			addr = net.JoinHostPort(addr, "80")
		}
		dconn, err = net.Dial("tcp", addr)
		if err != nil {
			return err
		}

		// Send request to destination server
		err = req.Write(dconn)
		if err != nil {
			return err
		}

		// Read the response of the destination server
		resp, err = http.ReadResponse(bufio.NewReader(dconn), req)
		if err != nil {
			return err
		}

		// Send response to source address
		resp = srv.onResponseFunc(resp)
		return resp.Write(sconn)
	default:
		return resp.Write(sconn)
	}
}

func (srv *Server) getCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if len(srv.certificates) < 1 {
		srv.certificates = make(map[string]*tls.Certificate, 0)
	}

	cert, ok := srv.certificates[chi.ServerName]
	if ok {
		return cert, nil
	}

	subCertPEM := bytes.NewBuffer(nil)
	subprivPEM := bytes.NewBuffer(nil)
	CreateSubCertificate(srv.certPEM, srv.privPEM, subCertPEM, subprivPEM, chi.ServerName)
	c, err := tls.X509KeyPair(subCertPEM.Bytes(), subprivPEM.Bytes())
	srv.certificates[chi.ServerName] = &c
	return &c, err
}
