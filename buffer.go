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

type buffer struct {
	buf []byte
	src io.Reader // also serve as broken flag
}

func newBuffer(r io.Reader) *buffer {
	return &buffer{
		buf: (*bufPool.Get().(*defaultBuffer))[:0],
		src: r,
	}
}

func (b *buffer) release() {
	if cap(b.buf) == defaultBufferSize {
		bufPool.Put((*defaultBuffer)(unsafe.Pointer(&b.buf[0])))
	}
}

func (b *buffer) attach(buf []byte) {
	b.buf = buf
}

func (b *buffer) detach() {
	b.buf = nil
}

func (b *buffer) detached() bool {
	return b.buf == nil
}

func (b *buffer) broken() bool {
	return b.src == nil
}

func (b *buffer) markBroken() {
	b.src = nil
}

// Detach the underlying buffer, return an io.ReadCloser to consume it from
// beginning. Caller should call Close() method on the returned io.ReadCloser
// afterwards. A nil io.ReadCloser will be returned if hijack failed.
func (b *buffer) Hijack() (rc io.ReadCloser) {
	if b.detached() {
		return
	}

	rc = newBufferReader(b.buf)
	b.detach()
	return
}

// Ensure at least n bytes is stored in the buffer. If any error occured while
// reading from the source io.Reader, a non-nil error will be returned, and the
// buffer will enter broken state. Calling Ensure() on a broken buffer will
// always fail.
func (b *buffer) Ensure(n int) (err error) {
	if b.detached() {
		return errBufferDetached
	}
	if b.broken() {
		return errReaderBroken
	}

	_len := len(b.buf)

	if n < _len {
		// already satisfied
		return
	}

	_cap := cap(b.buf)

	if n > _cap {
		// enlarge buffer
		_cap *= 2
		buf := make([]byte, _len, _cap)
		_ = copy(buf, b.buf)
		b.release()
		b.attach(buf)
	}

	read, err := io.ReadAtLeast(b.src, b.buf[_len:_cap], n-_len)
	if err != nil {
		b.markBroken()
	}
	b.buf = b.buf[:_len+read]
	return
}
