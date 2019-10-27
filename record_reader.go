package sni

const (
	ssl_v2 uint16 = 0x0002
	ssl_v3 uint16 = 0x0300

	handshake uint8 = 0x16
)

type recordReader struct {
	src    reader // also serve as broken flag
	remain int
	limit  int
}

var _ reader = &recordReader{}

func newRecordReader(r reader) *recordReader {
	return &recordReader{src: r, limit: -1}
}

func (rr *recordReader) broken() bool {
	return rr.src == nil
}

func (rr *recordReader) markBroken() {
	rr.src = nil
}

func (rr *recordReader) Limit(n int) error {
	if rr.broken() {
		return errReaderBroken
	}
	if n < 0 || 0 <= rr.limit && rr.limit < n {
		return errOutOfBoundary
	}
	rr.limit = n
	return nil
}

func (rr *recordReader) readRecordHeader() (err error) {
	var hdr []byte
	if hdr, err = rr.src.ReadN(5); err != nil {
		return
	}

	fragLen := uint16(hdr[3])<<8 | uint16(hdr[4])
	// zero-length handshake fragments are prohibited (since TLS 1.2)
	if fragLen == 0 {
		err = errInvalidRecord
		return
	}

	rr.remain = int(fragLen)
	return
}

func (rr *recordReader) readByte() (data byte, err error) {
	if rr.limit == 0 {
		err = errOutOfBoundary
		return
	} else if rr.limit > 0 {
		rr.limit--
	}

	if rr.remain <= 0 {
		if err = rr.readRecordHeader(); err != nil {
			return
		}
	}
	return rr.src.ReadByte()
}

func (rr *recordReader) ReadByte() (data byte, err error) {
	if rr.broken() {
		err = errReaderBroken
		return
	}
	data, err = rr.readByte()
	if err != nil {
		rr.markBroken()
		return
	}
	return
}

func (rr *recordReader) readN(n int) (data []byte, err error) {
	if n < 0 {
		err = errNegativeRead
		return
	}

	if n == 0 {
		return
	}

	if rr.limit >= 0 {
		if n > rr.limit {
			err = errOutOfBoundary
			return
		}
		rr.limit -= n
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
			off += len(chunk)
			n -= len(chunk)
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
		rr.remain -= n
		_ = copy(buf[off:], chunk)
		data = buf
	}
	return
}

func (rr *recordReader) ReadN(n int) (data []byte, err error) {
	if rr.broken() {
		err = errReaderBroken
		return
	}

	data, err = rr.readN(n)
	if err != nil {
		rr.markBroken()
	}
	return
}

func (rr *recordReader) skip(n int) (err error) {
	if n < 0 {
		return errNegativeRead
	}

	if n == 0 {
		return
	}

	if rr.limit >= 0 {
		if n > rr.limit {
			return errOutOfBoundary
		}
		rr.limit -= n
	}

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
	return
}

func (rr *recordReader) Skip(n int) error {
	if rr.broken() {
		return errReaderBroken
	}
	err := rr.skip(n)
	if err != nil {
		rr.markBroken()
	}
	return err
}
