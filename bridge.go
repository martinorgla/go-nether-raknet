package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
	"github.com/sandertv/go-raknet"
)

// bridge relays NetherNet connections accepted over LAN signaling to Geyser's RakNet listener.
//
// Geyser cannot be reached over NetherNet through a proxy: it requires the key of the NetherNet
// transport identity to match the key of the login, and only the console holds that key. Over RakNet
// the console cannot complete the encryption handshake, as it does not encrypt NetherNet sessions,
// so each session logs in to Geyser on the console's behalf (see session).
type bridge struct {
	log    *slog.Logger
	geyser string
	verify tokenVerifier
}

// advertise keeps the world card in the LAN tab in sync with Geyser's MOTD and player count.
func (b *bridge) advertise(ctx context.Context, d *discovery.Listener, name string, every time.Duration) {
	data := &discovery.ServerData{
		ServerName:            name,
		LevelName:             name,
		MaxPlayerCount:        10,
		AcceptsOnlineAuth:     true,
		AcceptsSelfSignedAuth: true,
		ConnectionType:        4,
	}
	d.ServerData(data)

	reachable := true
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		pingCtx, cancel := context.WithTimeout(ctx, every)
		pong, err := raknet.PingContext(pingCtx, b.geyser)
		cancel()
		switch {
		case err != nil && reachable:
			b.log.Warn("cannot ping Geyser, check that it runs with RakNet enabled (transport: raknet or both)", "addr", b.geyser, "err", err)
			reachable = false
		case err == nil:
			if !reachable {
				b.log.Info("Geyser is reachable again", "addr", b.geyser)
			}
			reachable = true
			if updateServerData(data, pong) {
				d.ServerData(data)
			} else {
				b.log.Debug("unexpected pong data", "data", string(pong))
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// updateServerData fills data from RakNet pong data in the form
// MCPE;motd;protocol;version;players;maxPlayers;guid;subMotd;gameMode;gameModeID;...
// It reports false if the pong data could not be parsed.
func updateServerData(data *discovery.ServerData, pong []byte) bool {
	parts := strings.Split(string(pong), ";")
	if len(parts) < 6 {
		return false
	}
	protocol, err1 := strconv.Atoi(parts[2])
	players, err2 := strconv.Atoi(parts[4])
	maxPlayers, err3 := strconv.Atoi(parts[5])
	if err := errors.Join(err1, err2, err3); err != nil {
		return false
	}
	data.ServerName = parts[1]
	data.LevelName = parts[1]
	if len(parts) > 7 && parts[7] != "" {
		data.LevelName = parts[7]
	}
	if len(parts) > 9 {
		if gameType, err := strconv.Atoi(parts[9]); err == nil {
			data.GameType = int32(gameType)
		}
	}
	data.Protocol = int32(protocol)
	data.Version = parts[3]
	data.PlayerCount = int32(players)
	data.MaxPlayerCount = int32(maxPlayers)
	return true
}

// handle dials Geyser for a client accepted over LAN, logs the client in and relays packets until
// either side closes.
func (b *bridge) handle(ctx context.Context, client *nethernet.Conn) {
	log := b.log.With("client", client.RemoteAddr().String())
	log.Info("client connected over LAN")
	defer client.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	server, err := raknet.DialContext(dialCtx, b.geyser)
	cancel()
	if err != nil {
		log.Error("cannot connect to Geyser", "addr", b.geyser, "err", err)
		return
	}
	defer server.Close()

	s, err := newSession(log, b.verify, client, server)
	if err != nil {
		log.Error("create session", "err", err)
		return
	}
	if err := s.login(ctx); err != nil {
		log.Error("login failed", "err", err)
		return
	}
	log.Info("logged in to Geyser, relaying")
	s.relay(ctx)
	log.Info("client disconnected")
}

func logClosed(log *slog.Logger, op string, err error) {
	if !errors.Is(err, net.ErrClosed) {
		log.Debug(op+" failed", "err", err)
	}
}
