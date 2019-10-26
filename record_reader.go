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

func (rr *recordReader) readRecordHeader() (err error) {
	var (
		hdr        []byte
		recordType uint8
		version    uint16
		fragLen    uint16
	)

	if hdr, err = rr.src.ReadN(5); err != nil {
		return
	}

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
	return

invalid:
	err = errInvalidRecord
	return
}

func (rr *recordReader) ReadByte() (data byte, err error) {
	if rr.remain <= 0 {
		if err = rr.readRecordHeader(); err != nil {
			return
		}
	}
	return rr.src.ReadByte()
}

func (rr *recordReader) ReadN(n int) (data []byte, err error) {
	if n < 0 {
		err = errNegativeRead
		return
	}

	if n == 0 {
		data = []byte{}
		return
	}

	if rr.remain <= 0 {
		if err = rr.readRecordHeader(); err != nil {
			return
		}
	}

	if n <= rr.remain {
		// intra-fragment, return a slice of underlying buffer
		rr.remain -= n
		data, err = rr.src.ReadN(n)
	} else {
		// inter-fragment, concatenate byte slices together
		var chunk []byte
		buf := make([]byte, n)
		off := 0

		for {
			if chunk, err = rr.src.ReadN(rr.remain); err != nil {
				return
			}
			_ = copy(buf[off:], chunk)
			off += rr.remain
			n -= rr.remain
			if err = rr.readRecordHeader(); err != nil {
				return
			}
			if n <= rr.remain {
				break
			}
		}

		if chunk, err = rr.src.ReadN(n); err != nil {
			return
		}
		_ = copy(buf[off:], chunk)
		rr.remain -= n
		data = buf
	}
	return
}

func (rr *recordReader) Skip(n int) (err error) {
	if n > 0 {
		if rr.remain <= 0 {
			if err = rr.readRecordHeader(); err != nil {
				return
			}
		}

		for n > rr.remain {
			if err = rr.src.Skip(rr.remain); err != nil {
				return
			}
			n -= rr.remain
			if err = rr.readRecordHeader(); err != nil {
				return
			}
		}

		if err = rr.src.Skip(n); err != nil {
			return
		}
		rr.remain -= n
	} else if n < 0 {
		err = errNegativeRead
	}
	return
}
