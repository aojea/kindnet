
package network

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	siocEthtool = 0x8946 // linux/sockios.h

	// #define ETHTOOL_SRXCSUM		0x00000015 /* Set RX hw csum enable (ethtool_value) */
	ethtoolSRxCsum = 0x00000015 // linux/ethtool.h
	// #define ETHTOOL_STXCSUM		0x00000017 /* Set TX hw csum enable (ethtool_value) */
	ethtoolSTxCsum = 0x00000017 // linux/ethtool.h

	maxIfNameSize = 16 // linux/if.h
)

// linux/if.h 'struct ifreq'
type ifreq struct {
	Name [maxIfNameSize]byte
	Data uintptr
}

// linux/ethtool.h 'struct ethtool_value'
type ethtoolValue struct {
	Cmd  uint32
	Data uint32
}

// ethtool executes Linux ethtool syscall.
func ethtool(iface string, cmd, val uint32) (retval uint32, err error) {
	if len(iface)+1 > maxIfNameSize {
		return 0, fmt.Errorf("interface name is too long")
	}
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(socket)

	// prepare ethtool request
	value := ethtoolValue{cmd, val}
	request := ifreq{Data: uintptr(unsafe.Pointer(&value))}
	copy(request.Name[:], iface)

	// ioctl system call
	_, _, errno := syscall.RawSyscall(syscall.SYS_IOCTL, uintptr(socket), uintptr(siocEthtool),
		uintptr(unsafe.Pointer(&request)))
	if errno != 0 {
		return 0, errno
	}
	return value.Data, nil
}

// SetChecksumOffloading enables/disables Rx/Tx checksum offloading
// for the given interface.
func SetChecksumOffloading(ifName string, rxOn, txOn bool) error {
	var rxVal, txVal uint32
	if rxOn {
		rxVal = 1
	}
	if txOn {
		txVal = 1
	}
	// If rx checksum isn't supported ignore and continue.
	if _, err := ethtool(ifName, ethtoolSRxCsum, rxVal); err != nil {
		if sErr, ok := err.(syscall.Errno); !ok || sErr != syscall.ENOTSUP {
			return err
		}
	}
	if _, err := ethtool(ifName, ethtoolSTxCsum, txVal); err != nil {
		return err
	}
	return nil
}
