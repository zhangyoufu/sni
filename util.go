package sni

func readUint8(r byteReader) uint8 {
	return r.ReadByte()
}

func readUint16(r byteReader) uint16 {
	return uint16(r.ReadByte())<<8 | uint16(r.ReadByte())
}

func readUint24(r byteReader) uint32 {
	return uint32(r.ReadByte())<<16 | uint32(r.ReadByte())<<8 | uint32(r.ReadByte())
}
