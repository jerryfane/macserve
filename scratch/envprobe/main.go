//go:build darwin

// Scratch native probe for v0.1.10 (do not merge).
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

type svc struct {
	Target    string
	PID       int
	Path      string
	Type      string
	EnvDict   map[string]string
	Inherited map[string]string
	Default   map[string]string
	Argv      []string
	Env       []string
	PPID      int
	UID       int
	Exec      string
	Platform  bool
	Err       string
}

func run(args ...string) string {
	out, err := exec.Command(args[0], args[1:]...).Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func procargs(pid int) (string, []string, []string, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil, nil, err
	}
	if len(raw) < 4 {
		return "", nil, nil, fmt.Errorf("short")
	}
	argc := int(binary.NativeEndian.Uint32(raw))
	exe, rest, _ := bytes.Cut(raw[4:], []byte{0})
	rest = bytes.TrimLeft(rest, "\x00")
	var argv, env []string
	for range argc {
		var a []byte
		a, rest, _ = bytes.Cut(rest, []byte{0})
		argv = append(argv, string(a))
	}
	for {
		var e []byte
		var ok bool
		e, rest, ok = bytes.Cut(rest, []byte{0})
		if !ok || len(e) == 0 {
			break
		}
		env = append(env, string(e))
	}
	return string(exe), argv, env, nil
}

func parsePrint(text string, s *svc) {
	s.EnvDict, s.Inherited, s.Default = map[string]string{}, map[string]string{}, map[string]string{}
	var cur map[string]string
	for _, line := range strings.Split(text, "\n") {
		if cur != nil {
			if line == "\t}" {
				cur = nil
				continue
			}
			if k, v, ok := strings.Cut(strings.TrimPrefix(line, "\t\t"), " => "); ok {
				cur[k] = v
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "\tpath = "):
			s.Path = strings.TrimPrefix(line, "\tpath = ")
		case strings.HasPrefix(line, "\ttype = "):
			s.Type = strings.TrimPrefix(line, "\ttype = ")
		case strings.HasPrefix(line, "\tpid = "):
			s.PID, _ = strconv.Atoi(strings.TrimPrefix(line, "\tpid = "))
		case line == "\tenvironment = {":
			cur = s.EnvDict
		case line == "\tinherited environment = {":
			cur = s.Inherited
		case line == "\tdefault environment = {":
			cur = s.Default
		}
	}
}

func inspect(target string) svc {
	s := svc{Target: target}
	text := run("/bin/launchctl", "print", target)
	if text == "" {
		s.Err = "print failed"
		return s
	}
	parsePrint(text, &s)
	if s.PID <= 0 {
		s.Err = "not running"
		return s
	}
	k, err := unix.SysctlKinfoProc("kern.proc.pid", s.PID)
	if err == nil {
		s.PPID, s.UID = int(k.Eproc.Ppid), int(k.Eproc.Ucred.Uid)
	}
	var flags uint32
	if _, _, errno := unix.Syscall6(unix.SYS_CSOPS, uintptr(s.PID), 0, uintptr(unsafe.Pointer(&flags)), unsafe.Sizeof(flags), 0, 0); errno == 0 {
		s.Platform = flags&1 != 0 && flags&0x04000000 != 0
	}
	exe, argv, env, err := procargs(s.PID)
	if err != nil {
		s.Err = err.Error()
	}
	s.Exec, s.Argv, s.Env = exe, argv, env
	return s
}

func list(domain string) []string {
	text := run("/bin/launchctl", "print", domain)
	in := false
	var labels []string
	for _, line := range strings.Split(text, "\n") {
		if line == "\tservices = {" {
			in = true
			continue
		}
		if in && line == "\t}" {
			break
		}
		if in {
			f := strings.Fields(line)
			if len(f) == 3 {
				if pid, err := strconv.Atoi(f[0]); err == nil && pid > 0 {
					labels = append(labels, domain+"/"+f[2])
				}
			}
		}
	}
	return labels
}

// domainPart is the process environment minus the service's own launchd
// environment dictionary keys and XPC_FLAGS.
func domainPart(s svc) []string {
	var out []string
	for _, e := range s.Env {
		k, _, _ := strings.Cut(e, "=")
		if _, ok := s.EnvDict[k]; ok || k == "XPC_FLAGS" {
			continue
		}
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func summarize(all []svc) {
	groups := map[string][]string{}
	var mismatched []string
	for _, s := range all {
		system := strings.HasPrefix(s.Path, "/System/Library/LaunchAgents/") && s.Type == "LaunchAgent"
		if !system || s.Err != "" {
			continue
		}
		// Does every dict entry appear verbatim in the process env?
		envset := map[string]bool{}
		for _, e := range s.Env {
			envset[e] = true
		}
		for k, v := range s.EnvDict {
			if !envset[k+"="+v] {
				mismatched = append(mismatched, fmt.Sprintf("%s dict %s=%s not in env", s.Target, k, v))
			}
		}
		key := strings.Join(domainPart(s), "\n")
		dom := strings.SplitN(s.Target, "/", 2)[0]
		groups[dom+"\n"+key] = append(groups[dom+"\n"+key], fmt.Sprintf("%s pid=%d ppid=%d platform=%v exec=%s", s.Target, s.PID, s.PPID, s.Platform, s.Exec))
	}
	fmt.Printf("SUMMARY %d distinct (domain, domain-part) groups among system LaunchAgents\n", len(groups))
	for k, v := range groups {
		fmt.Printf("=== GROUP size=%d\n%s\n--- members\n%s\n", len(v), k, strings.Join(v, "\n"))
	}
	for _, m := range mismatched {
		fmt.Println("DICT-MISMATCH", m)
	}
}

func main() {
	switch os.Args[1] {
	case "dump":
		var all []svc
		for _, d := range os.Args[2:] {
			for _, t := range list(d) {
				all = append(all, inspect(t))
			}
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		_ = enc.Encode(all)
	case "summarize":
		var all []svc
		if err := json.NewDecoder(os.Stdin).Decode(&all); err != nil {
			panic(err)
		}
		summarize(all)
	case "one":
		for _, t := range os.Args[2:] {
			s := inspect(t)
			b, _ := json.MarshalIndent(s, "", " ")
			fmt.Println(string(b))
			fmt.Printf("DOMAINPART %s %q\n", t, domainPart(s))
		}
	case "pid":
		for _, a := range os.Args[2:] {
			pid, _ := strconv.Atoi(a)
			exe, argv, env, err := procargs(pid)
			fmt.Printf("PID %d exe=%s argv=%q env=%q err=%v\n", pid, exe, argv, env, err)
		}
	}
}
