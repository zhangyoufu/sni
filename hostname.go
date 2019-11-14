package sni

import (
	"io"

	"github.com/zhangyoufu/sni/internal"
)

// ReadHostname() reads essential data from the provided io.Reader and extract
// SNI hostname via inspecting TLS handshake data. The data read from io.Reader
// is always returned in buf, regardless of SNI hostname extraction succeed or
// not.
func ReadHostname(r io.Reader) (hostname string, buf Buffer, err error) {
	var _buf []byte
	hostname, _buf, err = internal.ReadHostnameFastPath(r)
	if err == internal.ErrRetry {
		// FIXME: internal.ReadHostnameSlowPath is not implemented
        return
	}
	buf = newBuffer(_buf)
	return
}
