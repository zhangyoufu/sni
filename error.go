package sni

import "errors"

var (
	errAlreadyClosed       = errors.New("reader already closed")
	errInternalError       = errors.New("internal error")
	errInvalidRecord       = errors.New("invalid TLS record")
	errInvalidHandshake    = errors.New("invalid TLS handshake")
	errUnsupportedNameType = errors.New("unsupported SNI NameType")
)
