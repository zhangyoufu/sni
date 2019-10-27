package sni

import "io"

type reader interface {
	// ReadByte reads and returns the next byte. If ReadByte returns an error,
	// the returned byte value is undefined, the reader will enter broken state
	// and refuse any read/skip operations.
	ReadByte() (byte, error)

	// ReadN reads and returns exactly n bytes. A successful call returns nil
	// error, with len(data) == n guaranteed. If a non-nil error is returned,
	// the value of data is undefined, the reader will enter broken state and
	// refuse any read/skip operations.
	ReadN(n int) (data []byte, err error)

	// Skip exactly n bytes. A successful call returns a nil error. If a non-
	// nil error is returned, the reader will enter broken state and refuse
	// any read/skip operations.
	Skip(n int) error
}

var _ io.ByteReader = reader(nil)
