package internal

import (
	"sync"
	"unsafe"
)

// The length of a typical ClientHello message (incl. record header) is around
// 520 bytes (at the time of writing). We should offer a large enough initial
// buffer size to avoid out-of-bound read for fast-path, and reduce possible
// reallocations for slow-path.
const DefaultBufferSize = 768

type defaultBuffer = [DefaultBufferSize]byte

// A pool of byte arrays of same size.
var pool = sync.Pool{
	New: func() interface{} {
		return new(defaultBuffer)
	},
}

// Allocate a buffer with default size.
func AllocateBuffer() []byte {
	return (*pool.Get().(*defaultBuffer))[:]
}

// Caller should ensure buf[0] points to the beginning of buffer, i.e. buf has
// never been sliced with non-zero beginning offset.
func ReleaseBuffer(buf []byte) {
	pool.Put((*defaultBuffer)(unsafe.Pointer(&buf[0])))
}
