package sni

import "github.com/zhangyoufu/sni/internal"

// Buffer serves as a container for all data read from io.Reader during SNI
// hostname inspection.
type Buffer struct {
	buf []byte
}

func newBuffer(buf []byte) Buffer {
	return Buffer{
		buf: buf,
	}
}

// Bytes() returns all the data read from io.Reader in a single byte slice. The
// returned byte slice is valid until Release() is called.
func (b *Buffer) Bytes() []byte {
	return b.buf
}

// Release() should be called if the data inside Buffer is no longer needed.
// This allows implementation to recycle the underlying buffer space and
// improve the overall efficiency.
func (b *Buffer) Release() {
	if b.buf == nil {
		return
	}

	if cap(b.buf) == internal.DefaultBufferSize {
		internal.ReleaseBuffer(b.buf)
	}
	b.buf = nil
}
