package main

import (
	"io"
	"testing"
)

func TestCommandExitStatus(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "missing command", want: 2},
		{name: "help", args: []string{"--help"}, want: 0},
		{name: "controller unavailable", args: []string{"controller"}, want: 1},
		{name: "worker unavailable", args: []string{"worker"}, want: 1},
		{name: "controller help", args: []string{"controller", "--help"}, want: 0},
		{name: "worker short help", args: []string{"worker", "-h"}, want: 0},
		{name: "unsupported command", args: []string{"archive"}, want: 2},
		{name: "unexpected flag", args: []string{"worker", "--listen=:1234"}, want: 2},
		{name: "unexpected operand", args: []string{"controller", "start"}, want: 2},
		{name: "extra help argument", args: []string{"--help", "worker"}, want: 2},
		{name: "extra command help argument", args: []string{"worker", "--help", "start"}, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := run(tt.args, io.Discard, io.Discard); got != tt.want {
				t.Errorf("run(%q) exit status = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}
