package internal

import "io"

func ReadHostnameFastPath(r io.Reader) (hostname string, rcvd []byte, err error) {
	var (
		complete bool
		offset   int
		length   int
		extType  int
	)

	// prepare buffer
	buf := AllocateBuffer()

	// read once
	n, err := r.Read(buf)
	rcvd = buf[:n]
	if err != nil {
		// error or EOF
		return
	}

	if n < 1+2+2+1+3+2+32+1+0+2+2+1+1+2+2+2+2+1+2+3 {
		// the received part can not be a TLS ClientHello handshake with SNI
		// choose slow-path speculatively
		goto retry
	}

	// record content type
	if buf[0] != 0x16 {
		// fail early for non-TLS traffic
		goto invalid
	}

	// record version is not checked in fast-path implementation

	// record layer fragment length
	length = int(buf[3])<<8 | int(buf[4])
	if n > length+5 {
		// received more than one TLS record, choose slow-path speculatively
		goto retry
	}

	// handshake type is not checked in fast-path implementation
	// handshake length is not checked in fast-path implementation

	// session_id
	offset = 1 + 2 + 2 + 1 + 3 + 2 + 32
	length = int(buf[offset])
	offset += 1 + length

	// cipher_suites
	if n < offset+2+2+1+1+2+2+2+2+1+2+3 {
		// the received part is too short, choose slow-path speculatively
		goto retry
	}
	length = int(buf[offset])<<8 | int(buf[offset+1])
	offset += 2 + length

	// compression_methods
	if n < offset+1+1+2+2+2+2+1+2+3 {
		// the received part is too short, choose slow-path speculatively
		goto retry
	}
	length = int(buf[offset])
	offset += 1 + length

	// extensions
	if n < offset+2+2+2+2+1+2+3 {
		// the received part is too short, choose slow-path speculatively
		goto retry
	}
	length = int(buf[offset])<<8 | int(buf[offset+1])
	offset += 2

	if offset+length <= n {
		// ignore trailer after TLS extensions, if any
		n = offset + length

		// TLS extensions are received completely
		complete = true
	}

	// iterate over extensions
	for {
		if n < offset+2+2+2+1+2+3 {
			goto not_found_or_retry
		}
		extType = int(buf[offset])<<8 | int(buf[offset+1])
		length = int(buf[offset+2])<<8 | int(buf[offset+3])
		if extType == 0x0000 {
			break
		}
		offset += 2 + 2 + length
	}

	// SNI extension found
	// extension length is not checked in fast-path implementation
	// server name list length is not checked in fast-path implementation
	// name type is not checked in fast-path implementation

	offset += 2 + 2 + 2 + 1 + 2
	length = int(buf[offset-1]) // FQDN, upper byte of length field is ignored
	if n < offset+length {
		goto not_found_or_retry
	}
	hostname = string(buf[offset : offset+length])
	return

not_found_or_retry:
	if complete {
		err = ErrNotFound
		return
	}
	// fallthrough
retry:
	err = ErrRetry
	return
invalid:
	err = ErrNotFound
	return
}
