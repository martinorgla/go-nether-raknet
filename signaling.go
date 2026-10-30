package main

import (
	"context"
	"log/slog"
	"regexp"
	"strings"

	"github.com/df-mc/go-nethernet"
)

// identityLine matches the identity assertion attribute in an SDP.
var identityLine = regexp.MustCompile(`a=identity:[^\r\n]*\r\n`)

// lanSignaling adapts the answers produced by go-nethernet to what consoles send over LAN, and logs
// every signal exchanged with clients when debug logging is enabled.
type lanSignaling struct {
	nethernet.Signaling
	log *slog.Logger
	// keepIdentity keeps the 'a=identity' attribute in answers. Consoles send offers without one.
	keepIdentity bool
}

func (s lanSignaling) Signal(ctx context.Context, signal *nethernet.Signal) error {
	if signal.Type == nethernet.SignalTypeAnswer {
		c := *signal
		// go-nethernet writes inline candidates as "a=candidate:candidate:...", which consoles cannot parse.
		c.Data = strings.ReplaceAll(c.Data, "a=candidate:candidate:", "a=candidate:")
		if !s.keepIdentity {
			c.Data = identityLine.ReplaceAllString(c.Data, "")
		}
		signal = &c
	}
	s.log.Debug("signal to client", "signal", signal.String())
	return s.Signaling.Signal(ctx, signal)
}

func (s lanSignaling) Notify(n nethernet.Notifier) (stop func()) {
	return s.Signaling.Notify(loggingNotifier{Notifier: n, log: s.log})
}

type loggingNotifier struct {
	nethernet.Notifier
	log *slog.Logger
}

func (n loggingNotifier) NotifySignal(signal *nethernet.Signal) bool {
	n.log.Debug("signal from client", "signal", signal.String())
	return n.Notifier.NotifySignal(signal)
}
