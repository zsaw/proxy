package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type cmd byte

const (
	Connect cmd = iota + 1
	Bind
	Udp
)

type atyp byte

const (
	IPv4 atyp = iota + 1
	_
	Domain
	IPv6
)

type rep byte

const (
	Succeeded rep = iota
	GeneralSocks5ServerFailure
	ConnectionNotAllowedByRuleset
	NetworkUnreachable
	HostUnreachable
	ConnectionRefused
	TTLExpired
	CommandNotSupported
	AddressTypeNotSupported
)

func genAddrByAtyp(a atyp, addr string) ([]byte, error) {
	byts := make([]byte, 0)
	switch a {
	case IPv4:
		addr, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, err
		}

		as4 := addr.Addr().As4()
		for i := 0; i < len(as4); i++ {
			byts = append(byts, as4[i])
		}

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, addr.Port())
		byts = append(byts, port...)
	case IPv6:
		addr, err := netip.ParseAddrPort(addr)
		if err != nil {
			return Request{}, err
		}

		as6 := addr.Addr().As16()
		for i := 0; i < len(as6); i++ {
			byts = append(byts, as6[i])
		}

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, addr.Port())
		byts = append(byts, port...)
	case Domain:
		arr := strings.Split(addr, ":")
		if len(arr) != 2 {
			return nil, errors.New("domain format error")
		}

		byts = append(byts, byte(len(arr[0])))
		byts = append(byts, []byte(arr[0])...)

		uintp, err := strconv.ParseUint(arr[1], 10, 16)
		if err != nil {
			return nil, err
		}

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(uintp))
		byts = append(byts, port...)
	default:
		return nil, errors.New("unexpected atyp")
	}
	return byts, nil
}

func readAddrByAtyp(r io.Reader, a atyp) ([]byte, error) {
	var byts []byte
	var addr []byte
	port := make([]byte, 2)
	switch a {
	case IPv4:
		addr = make([]byte, 4)
	case IPv6:
		addr = make([]byte, 16)
	case Domain:
		num := make([]byte, 1)
		_, err := r.Read(num)
		if err != nil {
			return nil, err
		}
		byts = append(byts, num...)
		addr = make([]byte, num[0])
	}

	_, err := r.Read(addr)
	if err != nil {
		return nil, err
	}
	_, err = r.Read(port)
	if err != nil {
		return nil, err
	}

	byts = append(byts, addr...)
	byts = append(byts, port...)
	return byts, nil
}

func ReadRequest(r io.Reader) (Request, error) {
	req := make(Request, 4)
	_, err := r.Read(req)
	if err != nil {
		return nil, err
	}
	byts, err := readAddrByAtyp(r, atyp(req[3]))
	if err != nil {
		return nil, err
	}
	req = append(req, byts...)
	return req, nil
}

func NewRequest(c cmd, a atyp, addr string) (Request, error) {
	var byts Request
	byts = append(byts, 5, byte(c), 0, byte(a))
	b, err := genAddrByAtyp(a, addr)
	byts = append(byts, b...)
	return byts, err
}

type Request []byte

func (r Request) AddrType() atyp { return atyp(r[3]) }

func (r Request) Addr() string {
	switch r.AddrType() {
	case IPv4:
		addr := netip.AddrFrom4([4]byte{r[4], r[5], r[6], r[7]})
		addrport := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(r[8:]))
		return addrport.String()
	case IPv6:
		addr := netip.AddrFrom16([16]byte{r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15], r[16], r[17], r[18], r[19]})
		addrport := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(r[20:]))
		return addrport.String()
	case Domain:
		return fmt.Sprintf("%s:%d", r[5:5+r[4]], binary.BigEndian.Uint16(r[5+r[4]:]))
	default:
		return ""
	}
}

func ReadRespone(r io.Reader) (Respone, error) {
	resp := make(Respone, 4)
	_, err := r.Read(resp)
	if err != nil {
		return nil, err
	}
	byts, err := readAddrByAtyp(r, atyp(resp[3]))
	if err != nil {
		return nil, err
	}
	resp = append(resp, byts...)
	return resp, nil
}

func NewRespone(r rep, a atyp, addr string) (Respone, error) {
	var byts Respone
	byts = append(byts, 5, byte(r), 0, byte(a))
	b, err := genAddrByAtyp(a, addr)
	byts = append(byts, b...)
	return byts, err
}

type Respone []byte

func (r Respone) AddrType() atyp { return atyp(r[3]) }

func (r Respone) Addr() string {
	switch r.AddrType() {
	case IPv4:
		addr := netip.AddrFrom4([4]byte{r[4], r[5], r[6], r[7]})
		addrport := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(r[8:]))
		return addrport.String()
	case IPv6:
		addr := netip.AddrFrom16([16]byte{r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15], r[16], r[17], r[18], r[19]})
		addrport := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(r[20:]))
		return addrport.String()
	case Domain:
		return fmt.Sprintf("%s:%d", r[5:5+r[4]], binary.BigEndian.Uint16(r[5+r[4]:]))
	default:
		return ""
	}
}

func Client(conn net.Conn, dstAddr string) (net.Conn, error) {
	_, err := conn.Write([]byte{5, 1, 0})
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 2)
	conn.Read(msg)
	if err != nil {
		return nil, err
	}

	if msg[0] != 5 {
		return nil, errors.New("unsupported version")
	}

	switch msg[1] {
	case 0:
		req, err := NewRequest(Connect, IPv4, dstAddr)
		if err != nil {
			return nil, err
		}
		_, err = conn.Write(req)
		if err != nil {
			return nil, err
		}
		resp, err := ReadRespone(conn)
		if err != nil {
			return nil, err
		}

		switch resp[1] {
		case byte(Succeeded):
			return conn, nil
		default:
			return nil, errors.New("unknown rep")
		}
	default:
		return nil, errors.New("unsupported mthod")
	}
}
