
package main

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestEncodeWithAlignment(t *testing.T) {
	testCases := []struct {
		name     string
		input    interface{}
		expected []byte
	}{
		{
			"Uint16 - Max",
			uint16(65535),
			[]byte{0xff, 0xff, 0x00, 0x00},
		},
		{
			"Uint16 - With padding",
			uint16(5678),
			[]byte{0x16, 0x2e, 0x00, 0x00},
		},
		{
			"Uint32 - Max",
			uint32(4294967295),
			[]byte{0xff, 0xff, 0xff, 0xff},
		},
		{
			"Uint32",
			uint32(5678),
			[]byte{0x00, 0x00, 0x16, 0x2e},
		},
		{
			"IPv4",
			netip.MustParseAddr("1.1.1.1").AsSlice(),
			[]byte{0x01, 0x01, 0x01, 0x01},
		},
		{
			"IPv6",
			netip.MustParseAddr("::").AsSlice(),
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := encodeWithAlignment(tc.input)
			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %x, but got %x", tc.expected, result)
			}
		})
	}
}
