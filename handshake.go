package sni

import "io"

const (
	// OpenSSL
	client_hello_max_length = 131396

	// TLS
	client_hello uint8  = 0x01
	server_name  uint16 = 0x0000
	host_name    uint8  = 0x00
)

func ReadHostname(r io.Reader) (hostname string, rcvd io.ReadCloser, err error) {
	var (
		msgType         uint8
		msgLen          uint32
		sessIdLen       uint8
		cipherSuitesLen uint16
		compMethodsLen  uint8
		extsLen         uint16
		extType         uint16
		extLen          uint16
		svrNameListLen  uint16
		nameType        uint8
		hostNameLen     uint16
	)

	// error handling by returning is too verbose
	defer func() {
		if r := recover(); r != nil {
			if err, _ = r.(error); err == nil {
				panic(r)
			}
		}
	}()

	// save a copy of read data
	b := newBuffer(r)
	bv := newBufferViewer(b)

	// merge TLS records (fragments)
	rr := newRecordReader(bv)

	// struct Handshake

	msgType = readUint8(rr)
	if msgType != client_hello {
		goto invalid
	}

	msgLen = readUint24(rr)
	if msgLen > client_hello_max_length {
		goto invalid
	}
	// FIXME: rr.Limit(int(msgLen))

	// struct ClientHello

	// ProtocolVersion, Random
	rr.Skip(2 + 32)

	sessIdLen = readUint8(rr)
	if sessIdLen > 32 {
		goto invalid
	}
	if sessIdLen > 0 {
		rr.Skip(int(sessIdLen))
	}

	cipherSuitesLen = readUint16(rr)
	if strict {
		if cipherSuitesLen < 2 || cipherSuitesLen > 65534 {
			goto invalid
		}
	}
	rr.Skip(int(cipherSuitesLen))

	compMethodsLen = readUint8(rr)
	if strict {
		if compMethodsLen < 1 {
			goto invalid
		}
	}
	rr.Skip(int(compMethodsLen))

	extsLen = readUint16(rr)
	if strict {
		_ = extsLen
		// FIXME: rr.Limit(int(extsLen))
	}

	// iterate through TLS extensions to find SNI extension
	// duplicate extensions are not checked here
	for {
		extType = readUint16(rr)
		extLen = readUint16(rr)

		if extType == server_name {
			if strict {
				// FIXME: rr.Limit(int(extLen))
			}
			break
		}
		rr.Skip(int(extLen))
	}

	// struct ServerNameList
	svrNameListLen = readUint16(rr)
	if strict {
		_ = svrNameListLen
		// FIXME: rr.Limit(int(svrNameListLen))
	}

	// The definition of SNI-related structures is buggy. There is no way to
	// skip a ServerName structure whose name_type is not host_name(0).
	nameType = readUint8(rr)
	hostNameLen = readUint16(rr)
	if nameType != host_name {
		err = errUnsupportedNameType
		return
	}

	hostname = string(rr.ReadN(int(hostNameLen)))
	rcvd = b.Close()
	return

invalid:
	err = errInvalidHandshake
	return
}
