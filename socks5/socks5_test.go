package socks5

import (
	"testing"
)

func TestSocks5(t *testing.T) {
	err := ListenAndServe("")
	if err != nil {
		t.Error(err)
	}
}
