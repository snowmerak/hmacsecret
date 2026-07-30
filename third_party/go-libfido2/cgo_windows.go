//go:build windows && cgo

package libfido2

/*
#cgo windows pkg-config: libcbor libcrypto zlib
#cgo windows CFLAGS: -Inative/src
#cgo windows CFLAGS: -D_FIDO_INTERNAL -D_FIDO_MAJOR=1 -D_FIDO_MINOR=17 -D_FIDO_PATCH=0
#cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x0600
#cgo windows CFLAGS: -D_POSIX_C_SOURCE=200809L -D_BSD_SOURCE -D_GNU_SOURCE -D_DEFAULT_SOURCE
#cgo windows CFLAGS: -DHAVE_ASPRINTF -DHAVE_CLOCK_GETTIME -DHAVE_GETOPT
#cgo windows CFLAGS: -DHAVE_SIGNAL_H -DHAVE_UNISTD_H -DHAVE_CBOR_H -DHAVE_OPENSSLV_H
#cgo windows CFLAGS: -DUSE_WINHELLO -DWC_ERR_INVALID_CHARS=0x80
#cgo windows CFLAGS: -DOPENSSL_API_COMPAT=0x10100000L -DTLS=__thread
#cgo windows CFLAGS: -std=c99 -Wno-unused-parameter -Wno-type-limits
#cgo windows LDFLAGS: -lwsock32 -lws2_32 -lbcrypt -lsetupapi -lhid -lwinpthread
*/
import "C"
