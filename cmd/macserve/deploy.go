package main

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/jerryfane/macserve/internal/deploy"
)

func runDeployInstall(args []string, stdout, stderr io.Writer) int {
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "Usage: macserve deploy-install --env PATH --binary PATH --sha256 LOWERCASE_HEX --assets PATH [--apply]\nDefault: safe plan; --apply requires Darwin root, protected reviewed inputs and an absent deployment. Apply preserves read-only coexistence before/after evidence. No activation, PF writes, ACL, password or GUI changes. Network isolation is not enforced in phase 1.")
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		usage(stdout)
		return 0
	}
	var o deploy.Options
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		flag := args[i]
		if seen[flag] {
			fmt.Fprintf(stderr, "duplicate option: %s\n", flag)
			return 2
		}
		seen[flag] = true
		if flag == "--apply" {
			o.Apply = true
			continue
		}
		if flag != "--env" && flag != "--binary" && flag != "--sha256" && flag != "--assets" {
			usage(stderr)
			return 2
		}
		i++
		if i == len(args) || args[i] == "" {
			usage(stderr)
			return 2
		}
		value := args[i]
		if flag != "--sha256" {
			var err error
			value, err = filepath.Abs(value)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
		}
		switch flag {
		case "--env":
			o.EnvironmentPath = value
		case "--binary":
			o.BinaryPath = value
		case "--sha256":
			o.SHA256 = value
		case "--assets":
			o.AssetsPath = value
		}
	}
	if o.EnvironmentPath == "" || o.BinaryPath == "" || o.SHA256 == "" || o.AssetsPath == "" {
		usage(stderr)
		return 2
	}
	if err := deploy.Install(o, stdout, stderr); err != nil {
		fmt.Fprintf(stderr, "macserve deploy-install: %v\n", err)
		return 1
	}
	return 0
}
