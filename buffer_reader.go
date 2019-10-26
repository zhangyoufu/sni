package sni

import (
    "io"
    "unsafe"
)

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
