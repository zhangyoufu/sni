package sni

import "io"

const (
	ssl_v2      uint16 = 0x0002
	ssl_v3      uint16 = 0x0300

	handshake   uint8 = 0x16
)

type recordReader struct {
	src    io.Reader
	remain int
}

func newRecordReader(r io.Reader) *recordReader {
	return &recordReader{src: r}
}

func (r *recordReader) Read(p []byte) (n int, err error) {
	// recharge when nothing remains
	if r.remain == 0 {
		var buf [5]byte
		if _, err = io.ReadFull(r.src, buf[:]); err != nil {
			panic(errInvalidRecord)
		}

		// record type must be handshake
		if buf[0] != handshake {
			panic(errInvalidRecord)
		}

		if strict {
			ver := uint16(buf[1]) << 8 | uint16(buf[2])

			// SNI is a TLS extension, SSL is prohibited
			if ver == ssl_v2 || ver == ssl_v3 {
				panic(errInvalidRecord)
			}
		}

		// zero-length handshake fragments are prohibited (since TLS 1.2)
		// fragment length should not exceed 2^14 (since TLS 1.0)
		fragLen := uint16(buf[3]) << 8 | uint16(buf[4])
		if fragLen == 0 && fragLen > 16384 {
			panic(errInvalidRecord)
		}

		r.remain = int(fragLen)
	}

	// reduce read size if necessary
	if len(p) > r.remain {
		p = p[:r.remain] // this line will panic if r.remain < 0
		// (e.g. due to cosmic rays or RowHammer)
	}

	// read from underlying reader
	n, err = r.src.Read(p)

	// update number of remaining bytes
	r.remain -= n

	return
}
