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
		hostName        []byte
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

	if msgType, err = readUint8(rr); err != nil {
		return
	}
	if msgType != client_hello {
		goto invalid
	}

	if msgLen, err = readUint24(rr); err != nil {
		return
	}
	if msgLen > client_hello_max_length {
		goto invalid
	}
	// FIXME: rr.Limit(int(msgLen))

	// struct ClientHello

	// ProtocolVersion, Random
	if err = rr.Skip(2 + 32); err != nil {
		return
	}

	if sessIdLen, err = readUint8(rr); err != nil {
		return
	}
	if sessIdLen > 32 {
		goto invalid
	}
	if sessIdLen > 0 {
		if err = rr.Skip(int(sessIdLen)); err != nil {
			return
		}
	}

	if cipherSuitesLen, err = readUint16(rr); err != nil {
		return
	}
	if strict {
		if cipherSuitesLen < 2 || cipherSuitesLen > 65534 {
			goto invalid
		}
	}
	if err = rr.Skip(int(cipherSuitesLen)); err != nil {
		return
	}

	if compMethodsLen, err = readUint8(rr); err != nil {
		return
	}
	if strict {
		if compMethodsLen < 1 {
			goto invalid
		}
	}
	if err = rr.Skip(int(compMethodsLen)); err != nil {
		return
	}

	if extsLen, err = readUint16(rr); err != nil {
		return
	}
	if strict {
		_ = extsLen
		// FIXME: rr.Limit(int(extsLen))
	}

	// iterate through TLS extensions to find SNI extension
	// duplicate extensions are not checked here
	for {
		if extType, err = readUint16(rr); err != nil {
			return
		}
		if extLen, err = readUint16(rr); err != nil {
			return
		}

		if extType == server_name {
			if strict {
				// FIXME: rr.Limit(int(extLen))
			}
			break
		}
		if err = rr.Skip(int(extLen)); err != nil {
			return
		}
	}

	// struct ServerNameList
	if svrNameListLen, err = readUint16(rr); err != nil {
		return
	}
	if strict {
		_ = svrNameListLen
		// FIXME: rr.Limit(int(svrNameListLen))
	}

	// The definition of SNI-related structures is buggy. There is no way to
	// skip a ServerName structure whose name_type is not host_name(0).
	if nameType, err = readUint8(rr); err != nil {
		return
	}
	if hostNameLen, err = readUint16(rr); err != nil {
		return
	}
	if nameType != host_name {
		err = errUnsupportedNameType
		return
	}

	if hostName, err = rr.ReadN(int(hostNameLen)); err != nil {
		return
	}
	hostname = string(hostName)
	rcvd = b.Close()
	return

invalid:
	err = errInvalidHandshake
	return
}
