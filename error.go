package sni

import "errors"

var (
	errOutOfBoundary       = errors.New("out of boundary")
	errInvalidRecord       = errors.New("invalid TLS record")
	errInvalidHandshake    = errors.New("invalid TLS handshake")
	errUnsupportedNameType = errors.New("unsupported SNI NameType")
)
