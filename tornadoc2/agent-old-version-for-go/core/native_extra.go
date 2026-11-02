package core

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tornadoc2/agent/native"
	"tornadoc2/agent/protocol"
)

type (
	Task   = protocol.Task
	Result = protocol.Result
)

func lookPathNoExec(cmd string) (string, error) {
	if strings.ContainsAny(cmd, "/\\") {
		info, err := os.Stat(cmd)
		if err == nil && !info.IsDir() {
			return cmd, nil
		}
		return "", fmt.Errorf("not found: %s", cmd)
	}
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		pathEnv = "/usr/local/sbin:/usr/local/bin:/usr/sbin:" +
			"/usr/bin:/sbin:/bin"
	}
	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
	}
	exts := []string{""}
	if runtime.GOOS == "windows" {
		if pe := os.Getenv("PATHEXT"); pe != "" {
			exts = strings.Split(pe, ";")
		} else {
			exts = []string{".EXE", ".CMD", ".BAT", ".COM"}
		}
	}
	for _, dir := range strings.Split(pathEnv, sep) {
		if dir == "" {
			continue
		}
		for _, ext := range exts {
			candidate := filepath.Join(dir, cmd+ext)
			if info, err := os.Stat(candidate); err == nil &&
				!info.IsDir() {
				return candidate, nil
			}
		}
	}
	return "", fmt.Errorf("not found in PATH: %s", cmd)
}

func NativeFind(t Task) Result {
	spec := flagSpec{
		values: map[string]bool{
			"name": true, "size": true, "mtime": true, "type": true,
		},
	}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "find: " + err.Error()}
	}
	if len(pos) < 1 {
		return Result{ID: t.ID, Error: "find <path> [-name pat] [-size +N|-N] [-mtime -N|+N] [-type f|d]"}
	}
	root := pos[0]

	namePat := flags["name"]
	if namePat == "" && len(pos) > 1 {
		namePat = pos[1] // backwards-compat: positional pattern
	}

	var sizeCmp string
	var sizeVal int64
	if s := flags["size"]; s != "" {
		switch s[0] {
		case '+':
			sizeCmp, s = "+", s[1:]
		case '-':
			sizeCmp, s = "-", s[1:]
		}
		n, err := parseSizeSuffix(s)
		if err != nil {
			return Result{ID: t.ID, Error: "find -size: " + err.Error()}
		}
		sizeVal = n
	}

	var mtimeCmp string
	var mtimeDays int64
	if s := flags["mtime"]; s != "" {
		switch s[0] {
		case '+':
			mtimeCmp, s = "+", s[1:]
		case '-':
			mtimeCmp, s = "-", s[1:]
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return Result{ID: t.ID, Error: "find -mtime: invalid days"}
		}
		mtimeDays = n
	}

	typeFilter := flags["type"]

	var sb strings.Builder
	now := time.Now()
	_ = filepath.WalkDir(root,
		func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			info, ierr := d.Info()
			if ierr != nil {
				return nil
			}
			if typeFilter == "f" && info.IsDir() {
				return nil
			}
			if typeFilter == "d" && !info.IsDir() {
				return nil
			}
			if namePat != "" {
				if ok, _ := filepath.Match(namePat, d.Name()); !ok {
					return nil
				}
			}
			if sizeCmp != "" && !info.IsDir() {
				if sizeCmp == "+" && info.Size() <= sizeVal {
					return nil
				}
				if sizeCmp == "-" && info.Size() >= sizeVal {
					return nil
				}
			}
			if mtimeCmp != "" {
				days := now.Sub(info.ModTime()).Hours() / 24
				if mtimeCmp == "-" && days > float64(mtimeDays) {
					return nil
				}
				if mtimeCmp == "+" && days < float64(mtimeDays) {
					return nil
				}
			}
			sb.WriteString(p)
			sb.WriteByte('\n')
			return nil
		})
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeGrep(t Task) Result {
	spec := flagSpec{
		bools: map[string]bool{"r": true, "i": true, "l": true},
	}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "grep: " + err.Error()}
	}
	if len(pos) < 2 {
		return Result{ID: t.ID, Error: "grep <pattern> <path> [-r] [-i] [-l]"}
	}
	pat := pos[0]
	path := pos[1]
	if flags["i"] == "true" {
		pat = "(?i)" + pat
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return Result{ID: t.ID, Error: "regex: " + err.Error()}
	}
	listOnly := flags["l"] == "true"
	recursive := flags["r"] == "true"

	var sb strings.Builder

	grepFile := func(p string) {
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		lineno := 0
		matched := false
		for sc.Scan() {
			lineno++
			if re.MatchString(sc.Text()) {
				if listOnly {
					matched = true
					break
				}
				if recursive {
					fmt.Fprintf(&sb, "%s:%d:%s\n", p, lineno, sc.Text())
				} else {
					fmt.Fprintf(&sb, "%d:%s\n", lineno, sc.Text())
				}
			}
		}
		if listOnly && matched {
			sb.WriteString(p)
			sb.WriteByte('\n')
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	if info.IsDir() {
		if !recursive {
			return Result{ID: t.ID,
				Error: "grep: " + path + " is a directory (use -r)"}
		}
		_ = filepath.WalkDir(path,
			func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				grepFile(p)
				return nil
			})
	} else {
		grepFile(path)
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeHead(t Task) Result {
	spec := flagSpec{values: map[string]bool{"n": true}}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "head: " + err.Error()}
	}
	if len(pos) < 1 {
		return Result{ID: t.ID, Error: "head <file> [-n N]"}
	}
	path := pos[0]
	n := 20
	if s := flags["n"]; s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			return Result{ID: t.ID, Error: "head -n: invalid count"}
		}
		n = v
	} else if len(pos) > 1 {
		if v, err := strconv.Atoi(pos[1]); err == nil && v > 0 {
			n = v
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()
	var sb strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for i := 0; i < n && sc.Scan(); i++ {
		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeTail(t Task) Result {
	spec := flagSpec{values: map[string]bool{"n": true}}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "tail: " + err.Error()}
	}
	if len(pos) < 1 {
		return Result{ID: t.ID, Error: "tail <file> [-n N]"}
	}
	path := pos[0]
	n := 20
	if s := flags["n"]; s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 {
			return Result{ID: t.ID, Error: "tail -n: invalid count"}
		}
		n = v
	}
	if n == 0 {
		return Result{ID: t.ID, Output: encodeOutput(nil)}
	}

	f, err := os.Open(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	size := info.Size()
	if size == 0 {
		return Result{ID: t.ID, Output: encodeOutput(nil)}
	}

	const chunk = 8192
	// Read blocks backward until we have n+1 newlines, or hit offset 0.
	var buf []byte
	offset := size
	newlines := 0
	for offset > 0 && newlines <= n {
		readSize := int64(chunk)
		if offset < readSize {
			readSize = offset
		}
		offset -= readSize
		block := make([]byte, readSize)
		if _, err := f.ReadAt(block, offset); err != nil && err != io.EOF {
			return Result{ID: t.ID, Error: err.Error()}
		}
		buf = append(block, buf...)
		newlines = bytes.Count(buf, []byte{'\n'})
	}

	// Trim to the last n lines. If the file does not end in \n,
	// the final "line" is still a line.
	text := string(buf)
	if len(text) > 0 && text[len(text)-1] == '\n' {
		text = text[:len(text)-1]
	}
	lines := strings.Split(text, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if out != "" {
		out += "\n"
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func NativeStat(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "stat requires <path>"}
	}
	info, err := os.Stat(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	out := fmt.Sprintf(
		"Path:    %s\nSize:    %d\nMode:    %s\nModTime: %s\n"+
			"IsDir:   %v\n",
		t.Args[0], info.Size(), info.Mode().String(),
		info.ModTime().Format(time.RFC3339), info.IsDir())
	out += native.NativeStatExtra(t.Args[0])
	return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func NativeStrings(t Task) Result {
	spec := flagSpec{values: map[string]bool{"n": true}}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "strings: " + err.Error()}
	}
	if len(pos) < 1 {
		return Result{ID: t.ID, Error: "strings <file> [-n N]"}
	}
	path := pos[0]
	minLen := 4
	if s := flags["n"]; s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			return Result{ID: t.ID, Error: "strings -n: invalid min length"}
		}
		minLen = v
	}

	f, err := os.Open(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	if !info.Mode().IsRegular() {
		return Result{ID: t.ID,
			Error: "strings: not a regular file"}
	}

	var sb strings.Builder
	reader := bufio.NewReaderSize(f, 1024*1024)
	var cur []byte
	flush := func() {
		if len(cur) >= minLen {
			sb.Write(cur)
			sb.WriteByte('\n')
		}
		cur = cur[:0]
	}
	for {
		b, err := reader.ReadByte()
		if err != nil {
			break
		}
		if b >= 0x20 && b < 0x7f {
			cur = append(cur, b)
		} else {
			flush()
		}
	}
	flush()
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeHexdump(t Task) Result {
	spec := flagSpec{values: map[string]bool{"n": true, "o": true}}
	flags, pos, err := parseFlags(t.Args, spec)
	if err != nil {
		return Result{ID: t.ID, Error: "hexdump: " + err.Error()}
	}
	if len(pos) < 1 {
		return Result{ID: t.ID, Error: "hexdump <file> [-n N] [-o offset]"}
	}
	path := pos[0]
	maxBytes := int64(64 * 1024)
	var startOffset int64
	if s := flags["n"]; s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			return Result{ID: t.ID, Error: "hexdump -n: invalid count"}
		}
		maxBytes = v
	}
	if s := flags["o"]; s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			return Result{ID: t.ID, Error: "hexdump -o: invalid offset"}
		}
		startOffset = v
	}

	f, err := os.Open(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	if startOffset > 0 {
		if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
	}

	buf := make([]byte, maxBytes+1)
	n, _ := io.ReadFull(f, buf)
	data := buf[:n]
	truncated := int64(len(data)) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}

	var sb strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		fmt.Fprintf(&sb, "%08x  ", int64(i)+startOffset)
		for j := i; j < end; j++ {
			fmt.Fprintf(&sb, "%02x ", data[j])
		}
		for j := end; j < i+16; j++ {
			sb.WriteString("   ")
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			if data[j] >= 0x20 && data[j] < 0x7f {
				sb.WriteByte(data[j])
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	if truncated {
		fmt.Fprintf(&sb, "... truncated at %d bytes\n", maxBytes)
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeHash(t Task, algo string) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: algo + " requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()
	switch algo {
	case "sha1":
		h := sha1.New()
		if _, err := io.Copy(h, f); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte(hex.EncodeToString(h.Sum(nil))))}
	case "md5":
		h := md5.New()
		if _, err := io.Copy(h, f); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte(hex.EncodeToString(h.Sum(nil))))}
	case "sha256":
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		return Result{ID: t.ID, Output: encodeOutput(
			[]byte(hex.EncodeToString(h.Sum(nil))))}
	}
	return Result{ID: t.ID, Error: "unknown hash: " + algo}
}

func NativeReadlink(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "readlink requires <path>"}
	}
	target, err := os.Readlink(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(target + "\n"))}
}

func NativeRealpath(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "realpath requires <path>"}
	}
	abs, err := filepath.Abs(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		resolved = abs
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(resolved + "\n"))}
}

func NativeDu(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "du requires <path>"}
	}
	var total int64
	_ = filepath.Walk(t.Args[0],
		func(_ string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			total += info.Size()
			return nil
		})
	return Result{ID: t.ID, Output: encodeOutput(
		[]byte(fmt.Sprintf("%d\n", total)))}
}

func NativeMkdir(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "mkdir requires <path>"}
	}
	if err := os.MkdirAll(t.Args[0], 0755); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeRm(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "rm requires <path>"}
	}
	recursive := false
	paths := t.Args
	switch paths[0] {
	case "-r", "-rf", "-fr":
		recursive = true
		paths = paths[1:]
	}
	if len(paths) == 0 {
		return Result{ID: t.ID, Error: "rm requires <path>"}
	}
	var errs []string
	for _, p := range paths {
		var err error
		if recursive {
			err = os.RemoveAll(p)
		} else {
			err = os.Remove(p)
		}
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return Result{ID: t.ID, Error: strings.Join(errs, "; ")}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeCp(t Task) Result {
	if len(t.Args) < 2 {
		return Result{ID: t.ID, Error: "cp requires <src> <dst>"}
	}
	in, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer in.Close()
	out, err := os.Create(t.Args[1])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeMv(t Task) Result {
	if len(t.Args) < 2 {
		return Result{ID: t.ID, Error: "mv requires <src> <dst>"}
	}
	if err := os.Rename(t.Args[0], t.Args[1]); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeChmod(t Task) Result {
	if len(t.Args) < 2 {
		return Result{ID: t.ID, Error: "chmod requires <octal> <path>"}
	}
	mode, err := strconv.ParseUint(t.Args[0], 8, 32)
	if err != nil {
		return Result{ID: t.ID, Error: "invalid mode: " + err.Error()}
	}
	if err := os.Chmod(t.Args[1], os.FileMode(mode)); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeLn(t Task) Result {
	args := t.Args
	if len(args) > 0 && (args[0] == "-s" || args[0] == "-sf") {
		args = args[1:]
	}
	if len(args) < 2 {
		return Result{ID: t.ID, Error: "ln [-s] <target> <linkpath>"}
	}
	if err := os.Symlink(args[0], args[1]); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeTouch(t Task) Result {
	args := t.Args
	var refPath string
	if len(args) >= 3 && args[0] == "-r" {
		refPath = args[1]
		args = args[2:]
	}
	if len(args) < 1 {
		return Result{ID: t.ID, Error: "touch [-r <ref>] <path>"}
	}
	path := args[0]

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	f.Close()

	var atime, mtime time.Time
	if refPath != "" {
		refInfo, err := os.Stat(refPath)
		if err != nil {
			return Result{ID: t.ID,
				Error: "reference: " + err.Error()}
		}
		mtime = refInfo.ModTime()
		atime = mtime
	} else {
		mtime = time.Now()
		atime = mtime
	}

	if err := os.Chtimes(path, atime, mtime); err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte("ok\n"))}
}

func NativeWc(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "wc requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	var lines, words, bytes int64
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		lines++
		lineBytes := sc.Bytes()
		bytes += int64(len(lineBytes)) + 1
		words += int64(len(strings.Fields(string(lineBytes))))
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("%d %d %d %s\n",
			lines, words, bytes, t.Args[0])))}
}

func NativeNl(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "nl requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	var sb strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			sb.WriteByte('\n')
			continue
		}
		n++
		fmt.Fprintf(&sb, "%6d\t%s\n", n, line)
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeRev(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "rev requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	var sb strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		runes := []rune(line)
		for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
			runes[i], runes[j] = runes[j], runes[i]
		}
		sb.WriteString(string(runes))
		sb.WriteByte('\n')
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeSort(t Task) Result {
	args := t.Args
	numeric := false
	reverse := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-n":
			numeric = true
		case "-r":
			reverse = true
		case "-nr", "-rn":
			numeric = true
			reverse = true
		default:
			return Result{ID: t.ID,
				Error: "unknown flag: " + args[0]}
		}
		args = args[1:]
	}
	if len(args) < 1 {
		return Result{ID: t.ID,
			Error: "sort [-n] [-r] <file>"}
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if numeric {
		firstField := func(s string) (float64, bool) {
			f := strings.Fields(s)
			if len(f) == 0 {
				return 0, false
			}
			n, err := strconv.ParseFloat(f[0], 64)
			if err != nil {
				return 0, false
			}
			return n, true
		}
		sort.SliceStable(lines, func(i, j int) bool {
			ni, oki := firstField(lines[i])
			nj, okj := firstField(lines[j])
			if !oki || !okj {
				return lines[i] < lines[j]
			}
			return ni < nj
		})
	} else {
		sort.Strings(lines)
	}
	if reverse {
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
	}
	out := strings.Join(lines, "\n")
	if out != "" {
		out += "\n"
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(out))}
}

func NativeUniq(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "uniq requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	var sb strings.Builder
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var prev string
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first || line != prev {
			sb.WriteString(line)
			sb.WriteByte('\n')
			prev = line
			first = false
		}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeTr(t Task) Result {
	args := t.Args
	deleteMode := false
	if len(args) > 0 && (args[0] == "-d" || args[0] == "--delete") {
		deleteMode = true
		args = args[1:]
	}

	var set1, set2, path string
	if deleteMode {
		if len(args) < 2 {
			return Result{ID: t.ID, Error: "tr -d <set> <file>"}
		}
		set1, path = args[0], args[1]
	} else {
		if len(args) < 3 {
			return Result{ID: t.ID,
				Error: "tr <set1> <set2> <file>"}
		}
		set1, set2, path = args[0], args[1], args[2]
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}

	var out []byte
	if deleteMode {
		set := make(map[byte]bool, len(set1))
		for i := 0; i < len(set1); i++ {
			set[set1[i]] = true
		}
		for _, b := range data {
			if !set[b] {
				out = append(out, b)
			}
		}
	} else {
		if set2 == "" {
			return Result{ID: t.ID,
				Error: "tr: set2 must be non-empty"}
		}
		table := make(map[byte]byte, len(set1))
		for i := 0; i < len(set1); i++ {
			var to byte
			if i < len(set2) {
				to = set2[i]
			} else {
				to = set2[len(set2)-1]
			}
			table[set1[i]] = to
		}
		for _, b := range data {
			if r, ok := table[b]; ok {
				out = append(out, r)
			} else {
				out = append(out, b)
			}
		}
	}
	return Result{ID: t.ID, Output: encodeOutput(out)}
}

func NativeCksum(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "cksum requires <file>"}
	}
	f, err := os.Open(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	h := crc32.NewIEEE()
	n, err := io.Copy(h, f)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("%d %d %s\n", h.Sum32(), n, t.Args[0])))}
}

func NativeBase64(t Task) Result {
	mode := "e"
	stringMode := false
	i := 0
	for i < len(t.Args) && strings.HasPrefix(t.Args[i], "-") {
		switch t.Args[i] {
		case "-e", "--encode":
			mode = "e"
		case "-d", "--decode":
			mode = "d"
		case "-s", "--string":
			stringMode = true
		default:
			return Result{ID: t.ID,
				Error: "unknown flag: " + t.Args[i]}
		}
		i++
	}
	if i >= len(t.Args) {
		return Result{ID: t.ID,
			Error: "base64 [-e|-d] [-s] <file|string>"}
	}
	arg := t.Args[i]

	var data []byte
	var err error
	if stringMode {
		data = []byte(arg)
	} else {
		data, err = os.ReadFile(arg)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
	}

	if mode == "e" {
		out := base64.StdEncoding.EncodeToString(data)
		return Result{ID: t.ID,
			Output: encodeOutput([]byte(out + "\n"))}
	}
	decoded, err := base64.StdEncoding.DecodeString(
		strings.TrimSpace(string(data)))
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput(decoded)}
}

func NativeGzip(t Task, encode bool) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID,
			Error: "gzip/gunzip requires <file>"}
	}
	src := t.Args[0]
	var dst string
	if encode {
		dst = src + ".gz"
	} else {
		dst = strings.TrimSuffix(src, ".gz")
		if dst == src {
			dst = src + ".out"
		}
	}

	in, err := os.Open(src)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer out.Close()

	if encode {
		w := gzip.NewWriter(out)
		if _, err := io.Copy(w, in); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		if err := w.Close(); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
	} else {
		r, err := gzip.NewReader(in)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		if _, err := io.Copy(out, r); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		r.Close()
	}
	return Result{ID: t.ID,
		Output: encodeOutput([]byte(dst + "\n"))}
}

func NativeWhich(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID, Error: "which requires <cmd>"}
	}
	p, err := lookPathNoExec(t.Args[0])
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(p + "\n"))}
}

func NativeIfconfig(t Task) Result {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	var sb strings.Builder
	for _, iface := range ifaces {
		fmt.Fprintf(&sb, "%s  flags=%s  mtu=%d\n",
			iface.Name, iface.Flags.String(), iface.MTU)
		if len(iface.HardwareAddr) > 0 {
			fmt.Fprintf(&sb, "    ether %s\n",
				iface.HardwareAddr.String())
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			fmt.Fprintf(&sb, "    inet  %s\n", addr.String())
		}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func consumeArg(args []string, start int) (string, int) {
	if start >= len(args) {
		return "", start
	}
	first := args[start]
	if len(first) < 1 {
		return first, start + 1
	}
	q := first[0]
	if q != '"' && q != '\'' {
		return first, start + 1
	}
	if len(first) >= 2 && first[len(first)-1] == q {
		return first[1 : len(first)-1], start + 1
	}
	parts := []string{first}
	i := start + 1
	for i < len(args) {
		parts = append(parts, args[i])
		if len(args[i]) > 0 && args[i][len(args[i])-1] == q {
			i++
			break
		}
		i++
	}
	joined := strings.Join(parts, " ")
	if len(joined) >= 2 && joined[0] == q &&
		joined[len(joined)-1] == q {
		joined = joined[1 : len(joined)-1]
	}
	return joined, i
}

func NativeCurl(t Task) Result {
	args := t.Args
	var method, body, userAgent, outPath, url string
	var headers []string
	insecure := false
	includeHeaders := false
	followRedirects := false
	timeoutSecs := 30
	maxSize := 1024 * 1024

	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-X":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-X requires an argument"}
			}
			method = v
			i = ni
		case "-H":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-H requires an argument"}
			}
			headers = append(headers, v)
			i = ni
		case "-d":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-d requires an argument"}
			}
			body = v
			i = ni
		case "-A":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-A requires an argument"}
			}
			userAgent = v
			i = ni
		case "-k", "--insecure":
			insecure = true
			i++
		case "-i", "--include":
			includeHeaders = true
			i++
		case "-L", "--location":
			followRedirects = true
			i++
		case "-o":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-o requires a path"}
			}
			outPath = v
			i = ni
		case "-m":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-m requires seconds"}
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return Result{ID: t.ID,
					Error: "-m: invalid seconds"}
			}
			timeoutSecs = n
			i = ni
		case "--max-size":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "--max-size requires bytes"}
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return Result{ID: t.ID,
					Error: "--max-size: invalid bytes"}
			}
			maxSize = n
			i = ni
		default:
			if strings.HasPrefix(arg, "-") {
				return Result{ID: t.ID,
					Error: "unknown flag: " + arg}
			}
			if url != "" {
				return Result{ID: t.ID,
					Error: "only one URL may be supplied"}
			}
			url = arg
			i++
		}
	}

	if url == "" {
		return Result{ID: t.ID, Error: "curl requires a URL"}
	}

	if method == "" {
		if body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	} else {
		req.Header.Set("User-Agent", "curl/8.5.0")
	}

	for _, h := range headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return Result{ID: t.ID,
				Error: "invalid header (expected 'Name: Value'): " + h}
		}
		req.Header.Set(strings.TrimSpace(name), strings.TrimSpace(value))
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	}

	client := &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if !followRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, int64(maxSize)+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Result{ID: t.ID, Error: err.Error()}
	}
	truncated := len(data) > maxSize
	if truncated {
		data = data[:maxSize]
	}

	var sb strings.Builder
	if includeHeaders {
		fmt.Fprintf(&sb, "HTTP/%d.%d %s\n",
			resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		keys := make([]string, 0, len(resp.Header))
		for k := range resp.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range resp.Header[k] {
				fmt.Fprintf(&sb, "%s: %s\n", k, v)
			}
		}
		sb.WriteByte('\n')
	}

	if outPath != "" {
		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		fmt.Fprintf(&sb, "HTTP %s  %d bytes written to %s",
			resp.Status, len(data), outPath)
		if truncated {
			fmt.Fprintf(&sb, " (truncated at %d)", maxSize)
		}
		sb.WriteByte('\n')
	} else {
		if !includeHeaders {
			fmt.Fprintf(&sb, "HTTP %s\n", resp.Status)
		}
		sb.Write(data)
		if truncated {
			sb.WriteByte('\n')
			fmt.Fprintf(&sb, "... truncated at %d bytes\n", maxSize)
		} else if len(data) > 0 && data[len(data)-1] != '\n' {
			sb.WriteByte('\n')
		}
	}

	return Result{ID: t.ID,
		Output: encodeOutput([]byte(sb.String()))}
}

func NativeResolve(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID,
			Error: "resolve requires <host> [type]"}
	}
	host := t.Args[0]
	rtype := "A"
	if len(t.Args) > 1 {
		rtype = strings.ToUpper(t.Args[1])
	}

	ctx, cancel := context.WithTimeout(
		context.Background(), 10*time.Second)
	defer cancel()

	resolver := net.DefaultResolver
	var sb strings.Builder

	switch rtype {
	case "A", "AAAA":
		ips, err := resolver.LookupHost(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		for _, ip := range ips {
			isV4 := net.ParseIP(ip).To4() != nil
			if rtype == "A" && !isV4 {
				continue
			}
			if rtype == "AAAA" && isV4 {
				continue
			}
			fmt.Fprintf(&sb, "%s\n", ip)
		}
	case "CNAME":
		cname, err := resolver.LookupCNAME(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		fmt.Fprintf(&sb, "%s\n", cname)
	case "MX":
		mxs, err := resolver.LookupMX(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		for _, mx := range mxs {
			fmt.Fprintf(&sb, "%d %s\n", mx.Pref, mx.Host)
		}
	case "NS":
		nss, err := resolver.LookupNS(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		for _, ns := range nss {
			fmt.Fprintf(&sb, "%s\n", ns.Host)
		}
	case "TXT":
		txts, err := resolver.LookupTXT(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		for _, txt := range txts {
			fmt.Fprintf(&sb, "%s\n", txt)
		}
	case "PTR":
		names, err := resolver.LookupAddr(ctx, host)
		if err != nil {
			return Result{ID: t.ID, Error: err.Error()}
		}
		for _, name := range names {
			fmt.Fprintf(&sb, "%s\n", name)
		}
	default:
		return Result{ID: t.ID,
			Error: "unknown type: " + rtype +
				" (use A, AAAA, CNAME, MX, NS, TXT, or PTR)"}
	}

	if sb.Len() == 0 {
		return Result{ID: t.ID,
			Output: encodeOutput([]byte("(no records)\n"))}
	}
	return Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}

func NativeNc(t Task) Result {
	args := t.Args
	zeroIO := false
	sendData := ""
	timeout := 5 * time.Second

	i := 0
	for i < len(args) {
		arg := args[i]
		switch arg {
		case "-z":
			zeroIO = true
			i++
		case "-w":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "-w requires seconds"}
			}
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return Result{ID: t.ID,
					Error: "-w: invalid seconds"}
			}
			timeout = time.Duration(n) * time.Second
			i = ni
		case "--send":
			v, ni := consumeArg(args, i+1)
			if ni == i+1 {
				return Result{ID: t.ID,
					Error: "--send requires data"}
			}
			sendData = v
			i = ni
		default:
			if strings.HasPrefix(arg, "-") {
				return Result{ID: t.ID,
					Error: "unknown flag: " + arg}
			}
			if i+1 >= len(args) {
				return Result{ID: t.ID,
					Error: "nc requires <host> <port>"}
			}
			host := arg
			portStr := args[i+1]
			port, err := strconv.Atoi(portStr)
			if err != nil || port < 1 || port > 65535 {
				return Result{ID: t.ID,
					Error: "invalid port: " + portStr}
			}
			return ncDial(t, host, port, zeroIO, sendData, timeout)
		}
	}
	return Result{ID: t.ID, Error: "nc requires <host> <port>"}
}

func ncDial(t Task, host string, port int, zeroIO bool,
	sendData string, timeout time.Duration) Result {

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return Result{ID: t.ID,
			Error: fmt.Sprintf("connect failed: %v", err)}
	}
	defer conn.Close()

	if zeroIO {
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("open: %s\n", addr)))}
	}

	if sendData != "" {
		conn.SetWriteDeadline(time.Now().Add(timeout))
		if _, err := conn.Write([]byte(sendData)); err != nil {
			return Result{ID: t.ID,
				Error: fmt.Sprintf("write failed: %v", err)}
		}
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 64*1024)
	var received []byte
	for len(received) < 64*1024 {
		n, err := conn.Read(buf)
		if n > 0 {
			received = append(received, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	if len(received) == 0 {
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("open: %s (no data)\n", addr)))}
	}
	return Result{ID: t.ID, Output: encodeOutput(received)}
}

// ---------------------------------------------------------------------
// Persistent interactive shell

var (
	shellMu       sync.Mutex
	shellCmd      *exec.Cmd
	shellStdin    io.WriteCloser
	shellOutBuf   bytes.Buffer
	shellReaderWG sync.WaitGroup
	shellStartTS  time.Time
)

const shellSentinel = "__T2_SHELL_DONE__"
const shellOutCap = 4 * 1024 * 1024

func shellReaderLoop(r io.Reader) {
	defer shellReaderWG.Done()
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			shellMu.Lock()
			shellOutBuf.Write(buf[:n])
			if shellOutBuf.Len() > shellOutCap {
				data := shellOutBuf.Bytes()
				keep := make([]byte, len(data)/2)
				copy(keep, data[len(data)/2:])
				shellOutBuf.Reset()
				shellOutBuf.Write(keep)
			}
			shellMu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

// NativeShell dispatches on t.Args[0] for the four sub-verbs:
// start, exec, stop, status.
func NativeShell(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID,
			Error: "shell <start|exec|stop|status>"}
	}
	switch t.Args[0] {
	case "start":
		return shellStartVerb(t)
	case "exec":
		if len(t.Args) < 2 {
			return Result{ID: t.ID,
				Error: "shell exec requires a command"}
		}
		return shellExecVerb(t, strings.Join(t.Args[1:], " "))
	case "stop":
		return shellStopVerb(t)
	case "status":
		return shellStatusVerb(t)
	default:
		return Result{ID: t.ID,
			Error: "unknown shell subcommand: " + t.Args[0]}
	}
}

func shellStartVerb(t Task) Result {
	shellMu.Lock()
	defer shellMu.Unlock()

	if shellCmd != nil && shellCmd.Process != nil &&
		shellCmd.ProcessState == nil {
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			fmt.Sprintf("shell already running (pid %d)\n",
				shellCmd.Process.Pid)))}
	}
	shellCmd = nil
	shellStdin = nil
	shellOutBuf.Reset()

	var name string
	var argv []string
	if runtime.GOOS == "windows" {
		name = "cmd.exe"
		argv = []string{"/Q"}
	} else {
		name = "/bin/sh"
		argv = []string{"-s"}
	}

	cmd := exec.Command(name, argv...)
	cmd.Env = sanitizedEnv()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return Result{ID: t.ID,
			Error: "shell start: stdin pipe: " + err.Error()}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return Result{ID: t.ID,
			Error: "shell start: stdout pipe: " + err.Error()}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		stdin.Close()
		stdout.Close()
		return Result{ID: t.ID,
			Error: "shell start: stderr pipe: " + err.Error()}
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		stderr.Close()
		return Result{ID: t.ID,
			Error: "shell start: " + err.Error()}
	}

	shellCmd = cmd
	shellStdin = stdin
	shellOutBuf.Reset()
	shellStartTS = time.Now()

	shellReaderWG.Add(2)
	go shellReaderLoop(stdout)
	go shellReaderLoop(stderr)

	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("shell started: pid=%d %s\n",
			cmd.Process.Pid, name)))}
}

func shellExecVerb(t Task, cmdLine string) Result {
	shellMu.Lock()
	if shellCmd == nil {
		shellMu.Unlock()
		return Result{ID: t.ID, Error: "shell: no running shell — " +
			"use `shell start` first"}
	}

	shellOutBuf.Reset()

	var writePayload, sentinelLine string
	if runtime.GOOS == "windows" {
		writePayload = cmdLine + "\r\n"
		sentinelLine = "echo " + shellSentinel + "\r\n"
	} else {
		writePayload = cmdLine + "\n"
		sentinelLine = "echo " + shellSentinel + "\n"
	}

	_, werr := io.WriteString(shellStdin,
		writePayload+sentinelLine)
	shellMu.Unlock()

	if werr != nil {
		return Result{ID: t.ID,
			Error: "shell: write: " + werr.Error()}
	}

	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		shellMu.Lock()
		s := shellOutBuf.String()
		shellMu.Unlock()

		if idx := strings.Index(s, shellSentinel); idx >= 0 {
			out := strings.TrimRight(s[:idx], "\r\n")
			after := s[idx+len(shellSentinel):]
			after = strings.TrimLeft(after, "\r\n")

			shellMu.Lock()
			shellOutBuf.Reset()
			shellOutBuf.WriteString(after)
			shellMu.Unlock()

			if out == "" {
				out = "(no output)\n"
			} else {
				out += "\n"
			}
			return Result{ID: t.ID,
				Output: encodeOutput([]byte(out))}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return Result{ID: t.ID, Error: "shell: command timed out " +
		"after 120s. Use `shell stop` to close it."}
}

func shellStopVerb(t Task) Result {
	shellMu.Lock()
	if shellCmd == nil {
		shellMu.Unlock()
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			"shell not running\n"))}
	}
	cmd := shellCmd
	stdin := shellStdin

	var exitLine string
	if runtime.GOOS == "windows" {
		exitLine = "exit\r\n"
	} else {
		exitLine = "exit\n"
	}
	if stdin != nil {
		io.WriteString(stdin, exitLine)
	}
	shellCmd = nil
	shellStdin = nil
	shellOutBuf.Reset()
	shellMu.Unlock()

	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		<-done
	}
	shellReaderWG.Wait()

	ran := time.Since(shellStartTS).Round(time.Second)
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("shell stopped (ran %s)\n", ran)))}
}

func shellStatusVerb(t Task) Result {
	shellMu.Lock()
	defer shellMu.Unlock()
	if shellCmd == nil || shellCmd.Process == nil ||
		shellCmd.ProcessState != nil {
		return Result{ID: t.ID, Output: encodeOutput([]byte(
			"shell not running\n"))}
	}
	ran := time.Since(shellStartTS).Round(time.Second)
	return Result{ID: t.ID, Output: encodeOutput([]byte(
		fmt.Sprintf("shell running: pid=%d uptime=%s\n",
			shellCmd.Process.Pid, ran)))}
}

type flagSpec struct {
	bools  map[string]bool
	values map[string]bool
}

func parseFlags(args []string, spec flagSpec) (map[string]string, []string, error) {
	flags := make(map[string]string)
	var positional []string
	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			return flags, positional, nil
		}
		if len(arg) < 2 || arg[0] != '-' {
			positional = append(positional, arg)
			i++
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if spec.bools[name] {
			flags[name] = "true"
			i++
			continue
		}
		if spec.values[name] {
			if i+1 >= len(args) {
				return nil, nil, fmt.Errorf("flag -%s requires a value", name)
			}
			flags[name] = args[i+1]
			i += 2
			continue
		}
		return nil, nil, fmt.Errorf("unknown flag: %s", arg)
	}
	return flags, positional, nil
}

func parseSizeSuffix(s string) (int64, error) {
	if s == "" {
		return 0, fmt.Errorf("empty size")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'c':
		mult, s = 1, s[:len(s)-1]
	case 'k', 'K':
		mult, s = 1024, s[:len(s)-1]
	case 'M':
		mult, s = 1024*1024, s[:len(s)-1]
	case 'G':
		mult, s = 1024*1024*1024, s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n * mult, nil
}