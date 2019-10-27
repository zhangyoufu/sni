package sni

import "errors"

var (
	errBufferDetached   = errors.New("buffer detached")
	errReaderClosed     = errors.New("reader closed")
	errReaderBroken     = errors.New("reader broken due to previous error")
	errInvalidHandshake = errors.New("invalid TLS handshake")
	errInvalidRecord    = errors.New("invalid TLS record")
	errNegativeRead     = errors.New("negative read")
	errOutOfBoundary    = errors.New("out of boundary")
)
