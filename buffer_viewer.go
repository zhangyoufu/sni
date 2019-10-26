package sni

type bufferViewer struct {
	buf *buffer
	pos int // will never overflow for our use case
}

var _ reader = &bufferViewer{}

func newBufferViewer(buf *buffer) *bufferViewer {
	return &bufferViewer{buf: buf}
}

func (bv *bufferViewer) ReadByte() (data byte, err error) {
	begin := bv.pos
	end := begin + 1
	if err = bv.buf.Ensure(end); err != nil {
		return
	}
	bv.pos = end
	data = bv.buf.buf[begin]
	return
}

func (bv *bufferViewer) ReadN(n int) (data []byte, err error) {
	if n < 0 {
		err = errNegativeRead
		return
	}

	if n == 0 {
		data = []byte{}
		return
	}

	begin := bv.pos
	end := begin + n
	if err = bv.buf.Ensure(end); err != nil {
		return
	}
	bv.pos = end
	data = bv.buf.buf[begin:end]
	return
}

func (bv *bufferViewer) Skip(n int) (err error) {
	if n < 0 {
		err = errNegativeRead
		return
	}

	if n == 0 {
		return
	}

	bv.pos += n
	return
}
