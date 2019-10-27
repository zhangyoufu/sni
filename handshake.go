package sni

import "io"

const (
	client_hello_max_length        = 131396 // OpenSSL
	server_name             uint16 = 0x0000 // TLS Extension
)

// Read and parse TLS handshake ClientHello message from the provided io.Reader.
// SNI hostname will be extracted if available.
func ReadHostname(r io.Reader) (hostname string, rcvd io.ReadCloser, err error) {
	var buf []byte

	// save a copy of read data
	b := newBuffer(r)
	bv := newBufferViewer(b)

	// merge TLS record fragments
	rr := newRecordReader(bv)

	if buf, err = rr.ReadN(1 + 3 + 2 + 32 + 1); err != nil {
		return
	}

	// struct Handshake

	msgLen := uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
	if msgLen > client_hello_max_length {
		err = errInvalidHandshake
		return
	}
	if err = rr.Limit(int(msgLen) - 2 - 32 - 1); err != nil {
		return
	}

	// struct ClientHello

	sessIdLen := buf[38]
	if sessIdLen > 0 {
		if err = rr.Skip(int(sessIdLen)); err != nil {
			return
		}
	}

	if buf, err = rr.ReadN(2); err != nil {
		return
	}
	cipherSuitesLen := uint16(buf[0])<<8 | uint16(buf[1])
	if err = rr.Skip(int(cipherSuitesLen)); err != nil {
		return
	}

	var compMethodsLen uint8
	if compMethodsLen, err = rr.ReadByte(); err != nil {
		return
	}
	if err = rr.Skip(int(compMethodsLen) + 2); err != nil {
		return
	}

	// iterate through TLS extensions to find SNI extension
	// duplicate extensions are not checked here
	for {
		if buf, err = rr.ReadN(2 + 2); err != nil {
			return
		}
		extType := uint16(buf[0])<<8 | uint16(buf[1])
		extLen := uint16(buf[2])<<8 | uint16(buf[3])

		if extType == server_name {
			break
		}
		if err = rr.Skip(int(extLen)); err != nil {
			return
		}
	}

	// struct ServerNameList
	// struct ServerName

	if buf, err = rr.ReadN(2 + 1 + 2); err != nil {
		return
	}

	// The definition of SNI-related structures is buggy. There is no way
	// to skip a ServerName structure whose name_type is not host_name(0).

	hostNameLen := uint16(buf[3])<<8 | uint16(buf[4])
	if buf, err = rr.ReadN(int(hostNameLen)); err != nil {
		return
	}
	hostname = string(buf)
	rcvd = b.Hijack() // assume non-nil
	return
}
