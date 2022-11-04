package socks5

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"sync"
)

func newConn(conn net.Conn) {
	defer conn.Close()

	err := consult(conn)
	if err != nil {
		log.Println(err.Error())
		return
	}

	err = responseWriter(conn)
	if err != nil {
		log.Println(err.Error())
		return
	}
}

var ErrUnsupportedVersion = errors.New("unsupported version")

func consult(conn net.Conn) (err error) {
	msg := make([]byte, 2)
	_, err = conn.Read(msg)
	if err != nil {
		return err
	}

	if msg[0] != 5 {
		return ErrUnsupportedVersion
	}

	msg = make([]byte, msg[1])
	_, err = conn.Read(msg)
	if err != nil {
		return err
	}

	if bytes.IndexByte(msg, 0) < 0 {
		_, err = conn.Write([]byte{5, 0xff})
		if err != nil {
			return err
		}
		return errors.New("unsupported method")
	}

	_, err = conn.Write([]byte{5, 0})
	return err
}

func responseWriter(sconn net.Conn) error {
	req, err := ReadRequest(sconn)
	if err != nil {
		return err
	}
	switch req[1] {
	case byte(Connect):
		dconn, err := net.Dial("tcp", req.Addr())
		if err != nil {
			return err
		}
		resp, _ := NewRespone(Succeeded, req.AddrType(), req.Addr())
		_, err = sconn.Write(resp)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			_, err = io.Copy(dconn, sconn)
			if err != nil {
				return
			}
		}()
		go func() {
			_, err = io.Copy(sconn, dconn)
			if err != nil {
				return
			}
		}()
		wg.Wait()
		return nil
	case 2:
		return errors.New("bind method not supported")
	case 3:
		return errors.New("udp method not supported")
	default:
		return errors.New("unexpected cmd")
	}
}

func ListenAndServe(addr string) error {
	server := &Server{Addr: addr}
	return server.ListenAndServe()
}

type Server struct {
	Addr string
}

func (srv *Server) ListenAndServe() error {
	addr := srv.Addr
	if addr == "" {
		addr = ":1080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go newConn(conn)
	}
}
