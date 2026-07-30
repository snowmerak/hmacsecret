package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/snowmerak/hmacsecret/lib/hmacsecret"
	"github.com/snowmerak/hmacsecret/pkg/device/cli"
)

func TestSelectByIndex(t *testing.T) {
	var out bytes.Buffer
	s := &cli.Selector{
		In:         strings.NewReader("1\n"),
		Out:        &out,
		AutoSingle: false,
	}
	got, err := s.Select(context.Background(), []hmacsecret.DeviceInfo{
		{Index: 0, Path: "a", Product: "A"},
		{Index: 1, Path: "b", Product: "B"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "b" {
		t.Fatalf("path = %q", got.Path)
	}
	if !strings.Contains(out.String(), "[0]") || !strings.Contains(out.String(), "[1]") {
		t.Fatalf("listing missing: %s", out.String())
	}
}

func TestAutoSingle(t *testing.T) {
	s := &cli.Selector{
		In:         strings.NewReader(""),
		Out:        &bytes.Buffer{},
		AutoSingle: true,
	}
	got, err := s.Select(context.Background(), []hmacsecret.DeviceInfo{
		{Index: 0, Path: "only", Product: "X"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "only" {
		t.Fatalf("path = %q", got.Path)
	}
}
