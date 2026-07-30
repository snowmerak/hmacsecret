//go:build cgo && (linux || hmacsecret_libfido2)

package libfido2

/*
#cgo linux LDFLAGS: -L/usr/lib/x86_64-linux-gnu -lfido2
#cgo linux CFLAGS: -I/usr/include/fido
*/
import "C"
