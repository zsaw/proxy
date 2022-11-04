package socks5

import (
	"bytes"
	"encoding/binary"
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

	err = request(conn)
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

func request(conn net.Conn) (err error) {
	msg := make([]byte, 4)
	_, err = conn.Read(msg)
	if err != nil {
		return err
	}

	var addr []byte
	switch msg[3] {
	case 1:
		addr = make([]byte, 4)
		_, err = conn.Read(addr)
		if err != nil {
			return err
		}
	case 3:
		addr = make([]byte, msg[3])
		_, err = conn.Read(addr)
		if err != nil {
			return err
		}
	case 4:
		return errors.New("ipv6 is not supported")
	}

	port := make([]byte, 2)
	_, err = conn.Read(port)
	if err != nil {
		return err
	}

	switch msg[1] {
	case 1:
		err = connect(conn, addr, port)
		if err != nil {
			return err
		}
	case 2:
		return errors.New("bind method not supported")
	case 3:
		return errors.New("udp method not supported")
	default:
		return errors.New("unexpected cmd")
	}
	return nil
}

func connect(sconn net.Conn, a, p []byte) (err error) {
	addr := net.TCPAddr{
		IP:   a,
		Port: int(binary.BigEndian.Uint16(p)),
	}

	dconn, err := net.Dial("tcp", addr.String())
	if err != nil {
		return err
	}
	defer dconn.Close()

	msg := []byte{5, 0, 0, 1}
	msg = append(msg, a...)
	msg = append(msg, p...)
	_, err = sconn.Write(msg)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		_, err := io.Copy(dconn, sconn)
		if err != nil {
			log.Println(err.Error())
		}
		wg.Done()
	}()
	go func() {
		_, err := io.Copy(sconn, dconn)
		if err != nil {
			log.Println(err.Error())
		}
		wg.Done()
	}()

	wg.Wait()
	return err
}

func Listen() error {
	listen, err := net.Listen("tcp", ":1080")
	if err != nil {
		return err
	}
	defer listen.Close()

	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Println(err.Error())
			continue
		}
		go newConn(conn)
	}
}
