package sni

import (
	"bytes"
	"io"
)

const (
	// OpenSSL
	client_hello_max_length = 131396

	// TLS
	client_hello uint8  = 0x01
	server_name  uint16 = 0x0000
	host_name    uint8  = 0x00
)

func ReadHostname(r io.Reader) (hostname string, data []byte, err error) {
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
	var buf bytes.Buffer
	r = io.TeeReader(r, &buf)

	// merge TLS records (fragments)
	r = newRecordReader(r)

	reader := newFancyReader(r)

	// struct Handshake

	msgType = reader.ReadUint8()
	if msgType != client_hello {
		panic(errInvalidHandshake)
	}

	msgLen = reader.ReadUint24()
	if msgLen > client_hello_max_length {
		panic(errInvalidHandshake)
	}
	reader.Limit(int(msgLen))

	// struct ClientHello

	// ProtocolVersion, Random
	reader.Skip(2 + 32)

	sessIdLen = reader.ReadUint8()
	if sessIdLen > 32 {
		panic(errInvalidHandshake)
	}
	if sessIdLen > 0 {
		reader.Skip(int(sessIdLen))
	}

	cipherSuitesLen = reader.ReadUint16()
	if strict {
		if cipherSuitesLen < 2 || cipherSuitesLen > 65534 {
			panic(errInvalidHandshake)
		}
	}
	reader.Skip(int(cipherSuitesLen))

	compMethodsLen = reader.ReadUint8()
	if strict {
		if compMethodsLen < 1 {
			panic(errInvalidHandshake)
		}
	}
	reader.Skip(int(compMethodsLen))

	extsLen = reader.ReadUint16()
	if strict {
		reader.Limit(int(extsLen))
	}

	// iterate through TLS extensions to find SNI extension
	// duplicate extensions are not checked here
	for {
		extType = reader.ReadUint16()
		extLen = reader.ReadUint16()

		if extType == server_name {
			if strict {
				reader.Limit(int(extLen))
			}
			break
		}
		reader.Skip(int(extLen))
	}

	// struct ServerNameList
	svrNameListLen = reader.ReadUint16()
	if strict {
		reader.Limit(int(svrNameListLen))
	}

	// The definition of SNI-related structures is buggy. There is no way to
	// skip a ServerName structure whose name_type is not host_name(0).
	nameType = reader.ReadUint8()
	hostNameLen = reader.ReadUint16()
	if nameType != host_name {
		panic(errUnsupportedNameType)
	}

	hostname = string(reader.Peek(int(hostNameLen)))
	data = buf.Bytes()
	return
}
