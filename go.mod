module github.com/snowmerak/hmacsecret

go 1.26.5

require (
	github.com/keys-pub/go-libfido2 v1.5.3
	golang.org/x/term v0.34.0
)

require (
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

replace github.com/keys-pub/go-libfido2 => ./third_party/go-libfido2
