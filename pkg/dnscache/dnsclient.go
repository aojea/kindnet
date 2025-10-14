/*
Copyright YEAR The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package dnscache

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"syscall"

	"github.com/aojea/kindnet/pkg/network"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"
)

// copy from https://go.dev/src/net/dnsclient_unix.go

const (
	// to be used as a useTCP parameter to exchange
	useTCPOnly  = true
	useUDPOrTCP = false

	// Maximum DNS packet size.
	// Value taken from https://dnsflagday.net/2020/.
	maxDNSPacketSize = 1232
)

var (
	errNoSuchHost                = errors.New("no such host")
	errLameReferral              = errors.New("lame referral")
	errCannotUnmarshalDNSMessage = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage   = errors.New("cannot marshal DNS message")
	errInvalidDNSResponse        = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer     = errors.New("no answer from DNS server")
)

func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

func newTCPRequest(id uint16, q dnsmessage.Question) (tcpReq []byte, err error) {
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true, AuthenticData: false})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}

	tcpReq, err = b.Finish()
	if err != nil {
		return nil, err
	}
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return tcpReq, nil
}

func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, []byte, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, err
	}

	b = make([]byte, 1280) // 1280 is a reasonable initial size for IP over Ethernet, see RFC 4035
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, err
	}

	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}

	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, err
	}

	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, fmt.Errorf("parser start: %w %w", errCannotUnmarshalDNSMessage, err)
	}

	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, fmt.Errorf("questions section: %w %w", errCannotUnmarshalDNSMessage, err)
	}

	if err := p.SkipQuestion(); err != dnsmessage.ErrSectionDone {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, errInvalidDNSResponse
	}

	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, nil, errInvalidDNSResponse
	}
	return p, h, b[:n], nil
}

// checkHeader performs basic sanity checks on the header.
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	rcode, hasAdd := extractExtendedRCode(*p, h)

	if rcode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}

	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return fmt.Errorf("answers header: %w %v", errCannotUnmarshalDNSMessage, err)
	}

	// libresolv continues to the next server when it receives
	// an invalid referral response. See golang.org/issue/15434.
	if rcode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone && !hasAdd {
		return errLameReferral
	}

	if rcode != dnsmessage.RCodeSuccess && rcode != dnsmessage.RCodeNameError {
		// None of the error codes make sense
		// for the query we sent. If we didn't get
		// a name error and we didn't get success,
		// the server is behaving incorrectly or
		// having temporary trouble.
		if rcode == dnsmessage.RCodeServerFailure {
			return fmt.Errorf("server temporary mishbehaving, header %s extended rcode %v rcode ServerFailure", h.GoString(), hasAdd)
		}
		return fmt.Errorf("server mishbehaving, header rcode %d extended rcode %v rcode value %d", h.RCode, hasAdd, rcode)
	}

	return nil
}

// extractExtendedRCode extracts the extended RCode from the OPT resource (EDNS(0))
// If an OPT record is not found, the RCode from the hdr is returned.
// Another return value indicates whether an additional resource was found.
func extractExtendedRCode(p dnsmessage.Parser, hdr dnsmessage.Header) (dnsmessage.RCode, bool) {
	_ = p.SkipAllAnswers()
	_ = p.SkipAllAuthorities()
	hasAdd := false
	for {
		ahdr, err := p.AdditionalHeader()
		if err != nil {
			return hdr.RCode, hasAdd
		}
		hasAdd = true
		if ahdr.Type == dnsmessage.TypeOPT {
			return ahdr.ExtendedRCode(hdr.RCode), hasAdd
		}
		if err := p.SkipAdditional(); err != nil {
			return hdr.RCode, hasAdd
		}
	}
}

func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}

func dnsResponseRoundtrip(packet network.Packet, data []byte) error {
	// it must answer with the origin the DNS server used to cache
	// and destination the same original address
	freebindDialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{IP: packet.DstIP, Port: 53},
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
					klog.Infof("setting IP_TRANSPARENT: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
					klog.Infof("setting SO_REUSEPORT: %v", err)
				}
				if err := unix.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(noTrackMark)); err != nil {
					klog.Infof("setting SO_MARK: %v", err)
				}
			})
		},
	}
	conn, err := freebindDialer.Dial("udp", net.JoinHostPort(packet.SrcIP.String(), strconv.Itoa(packet.SrcPort)))
	if err != nil {
		return fmt.Errorf("can not dial to %s:%d : %w", packet.SrcIP.String(), packet.SrcPort, err)
	}
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("error writing to %s:%d : %w", packet.SrcIP.String(), packet.SrcPort, err)
	}
	return nil
}

func dnsBuildResponse(id uint16, q dnsmessage.Question, ips []net.IP) ([]byte, error) {
	hdr := dnsmessage.Header{
		ID:            id,
		Response:      true,
		Authoritative: true,
	}
	if len(ips) == 0 {
		hdr.RCode = dnsmessage.RCodeNameError
	}

	buf := []byte{}
	b := dnsmessage.NewBuilder(buf, hdr)
	b.EnableCompression()
	err := b.StartQuestions()
	if err != nil {
		return nil, err
	}
	err = b.Question(q)
	if err != nil {
		return nil, err

	}
	err = b.StartAnswers()
	if err != nil {
		return nil, err
	}
	rscHdr := dnsmessage.ResourceHeader{
		Name:  q.Name,
		Type:  q.Type,
		Class: q.Class,
		TTL:   30,
	}
	for _, ip := range ips {
		switch q.Type {
		case dnsmessage.TypeAAAA:
			err = b.AAAAResource(rscHdr, dnsmessage.AAAAResource{
				AAAA: [16]byte(ip.To16()),
			})
		case dnsmessage.TypeA:
			err = b.AResource(rscHdr, dnsmessage.AResource{
				A: [4]byte(ip.To4()),
			})
		}
	}
	if err != nil {
		return nil, err
	}

	return b.Finish()
}

func forwardDNSOverTCP(conn net.Conn, id uint16, q dnsmessage.Question) ([]net.IP, []byte, error) {
	tcpReq, err := newTCPRequest(id, q)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to build tcp request: %w", err)
	}

	p, h, udpResp, err := dnsStreamRoundTrip(conn, id, q, tcpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("stream roundtrip error: %w", err)
	}

	if err := checkHeader(&p, h); err != nil {
		if err == errNoSuchHost {
			return []net.IP{}, udpResp, nil
		} else {
			return nil, nil, fmt.Errorf("header error: %w", err)
		}
	}

	if err := skipToAnswer(&p, q.Type); err != nil {
		if err == errNoSuchHost {
			return []net.IP{}, udpResp, nil
		} else {
			return nil, nil, fmt.Errorf("error skipping to answers: %w", err)
		}
	}

	var gotIPs []net.IP
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return nil, nil, err

		}

		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, nil, err
			}
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, nil, err
			}
			gotIPs = append(gotIPs, r.AAAA[:])
		default:
			if err := p.SkipAnswer(); err != nil && err != dnsmessage.ErrSectionDone {
				klog.ErrorS(err, "can not unmarshall DNS header")
				continue
			}
		}
	}
	return gotIPs, udpResp, nil
}
