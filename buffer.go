package sni

import (
	"io"
	"sync"
	"unsafe"
)

// We reuse previously allocated buffers by putting them into a sync.Pool.
// Zeroing is omitted by resuing, so there should be some performance gain.
//
// The length of a typical ClientHello message (incl. record header) is around
// 520 bytes (at the time of writing). We should offer a large enough initial
// buffer size to avoid reallocations for most cases.
const defaultBufferSize = 768

type defaultBuffer [defaultBufferSize]byte

// A pool of byte arrays of same size.
var bufPool = sync.Pool{
	New: func() interface{} {
		return new(defaultBuffer)
	},
}

// bufferReader is not thread-safe. Close() should be called to return the
// buffer to the pool.
type bufferReader struct {
	buf []byte
	pos int // also serve as closed flag
}

var _ io.ReadCloser = &bufferReader{}

func newBufferReader(buf []byte) *bufferReader {
	return &bufferReader{buf: buf}
}

func (br *bufferReader) Read(p []byte) (n int, err error) {
	pos := br.pos
	if pos < 0 {
		err = errAlreadyClosed
	} else if pos == len(br.buf) {
		err = io.EOF
	} else {
		n = copy(p, br.buf[pos:])
		br.pos += n
	}
	return
}

func (br *bufferReader) Close() error {
	if br.pos < 0 {
		return errAlreadyClosed
	}
	br.pos = -1

	if cap(br.buf) == defaultBufferSize {
		// The buffer will be returned to the Pool.
		bufPool.Put((*defaultBuffer)(unsafe.Pointer(&br.buf[0])))
	}

	return nil
}

type buffer struct {
	buf []byte
	src io.Reader
}

func newBuffer(r io.Reader) *buffer {
	return &buffer{
		buf: (*bufPool.Get().(*defaultBuffer))[:0],
		src: r,
	}
}

func (b *buffer) Close() io.ReadCloser {
	return newBufferReader(b.buf)
}

func (b *buffer) Ensure(n int) (err error) {
	oldLen := len(b.buf)
	if n < oldLen {
		return
	}

	// enlarge buffer if necessary
	if n > cap(b.buf) {
		oldBuf := b.buf
		newBuf := make([]byte, cap(oldBuf)*2)
		_ = copy(newBuf, oldBuf)
		if cap(oldBuf) == defaultBufferSize {
			bufPool.Put((*defaultBuffer)(unsafe.Pointer(&oldBuf[0])))
		}
	}

	read, err := io.ReadAtLeast(b.src, b.buf[len(b.buf):cap(b.buf)], n-oldLen)
	if err != nil {
		return
	}
	b.buf = b.buf[:oldLen+read]
	return
}
