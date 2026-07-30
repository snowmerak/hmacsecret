package windows_test

import (
	"context"
	"testing"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	libsecrets "github.com/snowmerak/hmacsecret/lib/secrets"
	"github.com/snowmerak/hmacsecret/pkg/pin/windows"
)

func TestProvideEmpty(t *testing.T) {
	p := windows.New()
	pin, err := p.Provide(context.Background(), libsecrets.OpCreate, hmacsecret.DeviceInfo{Path: "windows://hello"})
	if err != nil {
		t.Fatal(err)
	}
	if pin != "" {
		t.Fatalf("pin = %q", pin)
	}
}
