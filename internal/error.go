package internal

import "errors"

var (
	ErrGiveUp   = errors.New("give up")
	ErrNotFound = errors.New("SNI hostname not found")
	ErrRetry    = errors.New("retry slow-path")
)
