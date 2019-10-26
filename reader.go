package sni

type byteReader interface {
	ReadByte() byte
}

type batchReader interface {
	ReadN(int) []byte
	Skip(int)
}

type reader interface {
	byteReader
	batchReader
}
