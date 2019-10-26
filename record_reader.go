package sni

const (
	ssl_v2 uint16 = 0x0002
	ssl_v3 uint16 = 0x0300

	handshake uint8 = 0x16
)

type recordReader struct {
	src    reader
	remain int
}

var _ reader = &recordReader{}

func newRecordReader(r reader) *recordReader {
	return &recordReader{src: r}
}

func (rr *recordReader) readRecordHeader() error {
	var (
		hdr		[]byte
		recordType	uint8
		version		uint16
		fragLen		uint16
	)

	hdr = rr.src.ReadN(5)

	recordType = hdr[0]
	if recordType != handshake {
		goto invalid
	}

	if strict {
		version = uint16(hdr[1])<<8 | uint16(hdr[2])
		// SNI is a TLS extension, SSL is prohibited
		if version == ssl_v2 || version == ssl_v3 {
			goto invalid
		}
	}

	fragLen = uint16(hdr[3])<<8 | uint16(hdr[4])
	// zero-length handshake fragments are prohibited (since TLS 1.2)
	if fragLen == 0 {
		goto invalid
	}
	// fragment length should not exceed 2^14 (since TLS 1.0)
	if strict && fragLen > 16384 {
		goto invalid
	}

	rr.remain = int(fragLen)
	return nil

invalid:
	return errInvalidRecord
}

func (rr *recordReader) ReadByte() byte {
	if rr.remain <= 0 {
		rr.readRecordHeader()
	}
	return rr.src.ReadByte()
}

func (rr *recordReader) ReadN(n int) []byte {
	if n == 0 {
		return []byte{}
	}
	if n < 0 {
		panic(errInternalError)
	}

	if rr.remain <= 0 {
		rr.readRecordHeader()
	}

	if n <= rr.remain {
		// intra-fragment, return a slice of underlying buffer
		rr.remain -= n
		return rr.src.ReadN(n)
	} else {
		// inter-fragment, concatenate byte slices together
		buf := make([]byte, n)
		off := 0

		for {
			copy(buf[off:], rr.src.ReadN(rr.remain))
			off += rr.remain
			n -= rr.remain
			rr.readRecordHeader()
			if n <= rr.remain {
				break
			}
		}

		copy(buf[off:], rr.src.ReadN(n))
		rr.remain -= n
		return buf
	}
}

func (rr *recordReader) Skip(n int) {
	if n == 0 {
		return
	}
	if n < 0 {
		panic(errInternalError)
	}

	if rr.remain <= 0 {
		rr.readRecordHeader()
	}

	for n > rr.remain {
		rr.src.Skip(rr.remain)
		n -= rr.remain
		rr.readRecordHeader()
	}

	rr.src.Skip(n)
	rr.remain -= n
}
