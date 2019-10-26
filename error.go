package sni

import "errors"

var (
	errAlreadyClosed       = errors.New("reader already closed")
	errNegativeRead        = errors.New("negative read")
	errInvalidRecord       = errors.New("invalid TLS record")
	errInvalidHandshake    = errors.New("invalid TLS handshake")
	errUnsupportedNameType = errors.New("unsupported SNI NameType")
)
