package sni

type bufferViewer struct {
	buf *buffer
	pos int // will never overflow for our use case
}

var _ reader = &bufferViewer{}

func newBufferViewer(buf *buffer) *bufferViewer {
	return &bufferViewer{buf: buf}
}

func (bv *bufferViewer) ReadByte() byte {
	begin := bv.pos
	end := begin + 1
	bv.buf.Ensure(end)
	bv.pos = end
	return bv.buf.buf[begin]
}

func (bv *bufferViewer) ReadN(n int) []byte {
	if n <= 0 {
		panic(errInternalError)
	}
	begin := bv.pos
	end := begin + n
	bv.buf.Ensure(end)
	bv.pos = end
	return bv.buf.buf[begin:end]
}

func (bv *bufferViewer) Skip(n int) {
	if n <= 0 {
		panic(errInternalError)
	}
	bv.pos += n
}
