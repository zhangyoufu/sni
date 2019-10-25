package sni

import (
	"bufio"
	"io"
)

type fancyReader struct {
	src   *bufio.Reader
	limit int
}

func newFancyReader(r io.Reader) *fancyReader {
	return &fancyReader{
		src:   bufio.NewReader(r), // defaultBufSize = 4096, len(fqdn) < 253
		limit: -1,
	}
}

func (r *fancyReader) Limit(n int) {
	if n < 0 || 0 <= r.limit && r.limit < n {
		panic(errOutOfBoundary)
	}
	r.limit = n
}

func (r *fancyReader) Skip(n int) {
	if n < 0 {
		panic(errOutOfBoundary)
	}
	if r.limit >= 0 {
		if n > r.limit {
			panic(errOutOfBoundary)
		}
		r.limit -= n
	}
	if _, err := r.src.Discard(n); err != nil {
		panic(err)
	}
}

// The byte slice return has a short lifespan. Use with caution.
func (r *fancyReader) Peek(n int) []byte {
	if n < 0 || 0 <= r.limit && r.limit < n {
		panic(errOutOfBoundary)
	}
	data, err := r.src.Peek(n)
	if err != nil {
		panic(err)
	}
	return data
}

func (r *fancyReader) next() byte {
	switch {
	case r.limit == 0:
		panic(errOutOfBoundary)
	case r.limit > 0:
		r.limit--
	}
	data, err := r.src.ReadByte()
	if err != nil {
		panic(err)
	}
	return data
}

func (r *fancyReader) ReadUint8() uint8 {
	return r.next()
}

func (r *fancyReader) ReadUint16() uint16 {
	return uint16(r.next())<<8 | uint16(r.next())
}

func (r *fancyReader) ReadUint24() uint32 {
	return uint32(r.next())<<16 | uint32(r.next())<<8 | uint32(r.next())
}
