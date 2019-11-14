# Introduction

This package helps extracting SNI hostname from io.Reader. The data read from io.Reader is also returned to caller. This package is intended to be used as a building block of SNI proxy.

# Known Issue

There is no slow-path implementation in this package currently. I am willing to write one if there is any legal requests that fast-path cannot handle.

# Reference

* [TLS 1.0](https://tools.ietf.org/html/rfc2246)
* [TLS 1.1](https://tools.ietf.org/html/rfc4346)
* [TLS 1.2](https://tools.ietf.org/html/rfc5246)
* [TLS 1.3](https://tools.ietf.org/html/rfc8446)
* [SNI](https://tools.ietf.org/html/rfc6066)
