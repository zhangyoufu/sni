package sni

import "io"

func readUint8(r io.ByteReader) (uint8, error) {
	return r.ReadByte()
}

func readUint16(r io.ByteReader) (data uint16, err error) {
	b1, err := r.ReadByte()
	if err != nil {
		return
	}
	b0, err := r.ReadByte()
	if err != nil {
		return
	}
	data = uint16(b1)<<8 | uint16(b0)
	return
}

func readUint24(r io.ByteReader) (data uint32, err error) {
	b2, err := r.ReadByte()
	if err != nil {
		return
	}
	b1, err := r.ReadByte()
	if err != nil {
		return
	}
	b0, err := r.ReadByte()
	if err != nil {
		return
	}
	data = uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	return
}
