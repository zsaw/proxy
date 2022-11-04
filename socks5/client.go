package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
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

func NewRequest(c cmd, a atyp, addr string) (Request, error) {
	var byts Request
	byts = append(byts, 5, byte(c), 0, byte(a))

	switch a {
	case IPv4:
		addr, err := netip.ParseAddrPort(addr)
		if err != nil {
			return Request{}, err
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
			return Request{}, errors.New("domain format error")
		}

		byts = append(byts, byte(len(arr[0])))
		byts = append(byts, []byte(arr[0])...)

		uintp, err := strconv.ParseUint(arr[1], 10, 16)
		if err != nil {
			return Request{}, err
		}

		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, uint16(uintp))
		byts = append(byts, port...)
	default:
		return Request{}, errors.New("unexpected atyp")
	}

	return byts, nil
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
		return "unexpected atyp"
	}
}
