package sni

import "io"

type reader interface {
	io.ByteReader
	ReadN(int) ([]byte, error)
	Skip(int) error
}
