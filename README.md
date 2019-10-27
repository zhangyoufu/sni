# Introduction

This package helps extracting SNI hostname from io.Reader. The data read from io.Reader is also returned to caller. This package is intended to be used as a building block of SNI proxy.

Clone this repo, `go run github.com/zhangyoufu/sni/cmd/demo`, and access [https://localhost:8443](https://localhost:8443) to see it running.

# Interface

```
func ReadHostname(io.Reader) (hostname string, rcvd io.ReadCloser, err error)
```

# Design

```
(io.Reader) --> buffer --> bufferViewer (reader) --> recordReader (reader) --> Handshake & ClientHello
                  |
                  v
             bufferReader
            (io.ReadCloser)
```

# Reference

* [TLS 1.0](https://tools.ietf.org/html/rfc2246)
* [TLS 1.1](https://tools.ietf.org/html/rfc4346)
* [TLS 1.2](https://tools.ietf.org/html/rfc5246)
* [TLS 1.3](https://tools.ietf.org/html/rfc8446)
* [SNI](https://tools.ietf.org/html/rfc6066)
