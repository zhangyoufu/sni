package sni

type bufferViewer struct {
	buf *buffer // also serve as broken flag
	pos int     // will never overflow for our use case
}

var _ reader = &bufferViewer{}

func newBufferViewer(buf *buffer) *bufferViewer {
	return &bufferViewer{buf: buf}
}

func (bv *bufferViewer) broken() bool {
	return bv.buf == nil
}

func (bv *bufferViewer) markBroken() {
	bv.buf = nil
}

func (bv *bufferViewer) readByte() (data byte, err error) {
	pos := bv.pos
	next := pos + 1
	if err = bv.buf.Ensure(next); err != nil {
		return
	}
	data = bv.buf.buf[pos]
	bv.pos = next
	return
}

func (bv *bufferViewer) ReadByte() (data byte, err error) {
	if bv.broken() {
		err = errReaderBroken
		return
	}
	data, err = bv.readByte()
	if err != nil {
		bv.markBroken()
	}
	return
}

func (bv *bufferViewer) readN(n int) (data []byte, err error) {
	if n < 0 {
		err = errNegativeRead
		return
	}

	if n == 0 {
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

func (bv *bufferViewer) ReadN(n int) (data []byte, err error) {
	if bv.broken() {
		err = errReaderBroken
		return
	}
	data, err = bv.readN(n)
	if err != nil {
		bv.markBroken()
	}
	return
}

func (bv *bufferViewer) skip(n int) (err error) {
	if n < 0 {
		return errNegativeRead
	}

	if n == 0 {
		return
	}

	bv.pos += n
	return
}

func (bv *bufferViewer) Skip(n int) error {
	if bv.broken() {
		return errReaderBroken
	}
	err := bv.skip(n)
	if err != nil {
		bv.markBroken()
	}
	return err
}
