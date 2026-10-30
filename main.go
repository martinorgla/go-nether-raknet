// Command nether-bridge makes a Geyser server visible in the LAN tab of Minecraft: Bedrock Edition
// clients (Xbox, Switch, PlayStation, ...) from version 26.60 onwards.
//
// Since 26.60 the game discovers LAN worlds with NetherNet broadcasts on UDP port 7551 and uses the
// same port for WebRTC signaling. Geyser does not listen there, so it never shows up in the LAN tab.
// nether-bridge answers the LAN broadcasts on Geyser's behalf, accepts the NetherNet connection of
// the console and relays it to Geyser's RakNet listener.
package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
	"github.com/pion/webrtc/v4"
)

func main() {
	var (
		lanAddr      = flag.String("lan", "0.0.0.0:7551", "UDP address to answer LAN discovery and signaling on")
		geyserAddr   = flag.String("geyser", "127.0.0.1:19132", "UDP address of Geyser's RakNet listener")
		identityFile = flag.String("identity", "nether-bridge-identity.pem", "file holding the server key shown to clients (created if missing)")
		icePort      = flag.Int("ice-port", 7552, "UDP port for the WebRTC connections of consoles (allow it in the firewall), 0 picks random ports")
		name         = flag.String("name", "Geyser", "world name shown in the LAN tab until Geyser answers a ping")
		statusEvery  = flag.Duration("status-interval", 5*time.Second, "how often to refresh the MOTD and player count from Geyser")
		trickle      = flag.Bool("trickle", false, "send ICE candidates in separate signals instead of inline in the answer")
		keepIdentity = flag.Bool("identity-assertion", false, "include the server identity assertion in answers")
		debug        = flag.Bool("debug", false, "enable debug logging")
	)
	flag.Parse()
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "unexpected argument %q: every flag must be followed by its value, e.g. -debug -geyser 127.0.0.1:19132\n", flag.Arg(0))
		os.Exit(2)
	}
	if _, _, err := net.SplitHostPort(*geyserAddr); err != nil {
		fmt.Fprintf(os.Stderr, "invalid -geyser address %q: %v\n", *geyserAddr, err)
		os.Exit(2)
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if err := run(log, *lanAddr, *geyserAddr, *identityFile, *name, *icePort, *statusEvery, lanOptions{trickle: *trickle, keepIdentity: *keepIdentity}); err != nil {
		log.Error("nether-bridge stopped", "err", err)
		os.Exit(1)
	}
}

// lanOptions tunes how answers are sent to consoles.
type lanOptions struct {
	trickle      bool
	keepIdentity bool
	// verify verifies the multiplayer tokens of consoles. It defaults to Minecraft's authorization service.
	verify tokenVerifier
}

func run(log *slog.Logger, lanAddr, geyserAddr, identityFile, name string, icePort int, statusEvery time.Duration, opts lanOptions) error {
	if opts.verify == nil {
		opts.verify = &xboxVerifier{}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	key, err := loadOrCreateKey(identityFile)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	api, closeAPI, err := newWebRTCAPI(icePort)
	if err != nil {
		return err
	}
	defer closeAPI()

	d, err := discovery.ListenConfig{
		NetworkID: rand.Uint64(),
		Log:       log.With("src", "discovery"),
	}.Listen(lanAddr)
	if err != nil {
		return fmt.Errorf("listen for LAN discovery on %s: %w", lanAddr, err)
	}
	defer d.Close()

	log.Info("nether-bridge started", "lan", lanAddr, "ice-port", icePort, "geyser", geyserAddr)
	return serve(ctx, log, d, api, geyserAddr, key, name, statusEvery, opts)
}

// serve accepts NetherNet connections signaled over the LAN discovery listener d and relays them to
// Geyser until ctx is cancelled.
func serve(ctx context.Context, log *slog.Logger, d *discovery.Listener, api *webrtc.API, geyserAddr string, key *ecdsa.PrivateKey, name string, statusEvery time.Duration, opts lanOptions) error {
	l, err := nethernet.ListenConfig{
		Log: log.With("src", "listener"),
		API: api,
		IssueServerIdentity: func(context.Context) (*nethernet.Identity, error) {
			return nethernet.ServerIdentity(key, "self")
		},
		// Consoles joining over LAN send offers without an identity assertion. The login is still
		// verified by Geyser, which binds it to the player's key through the RakNet encryption handshake.
		AllowAnonymous: true,
		// Consoles put their candidates inline in the offer, so answer the same way by default.
		DisableTrickleICE: !opts.trickle,
		// Leave room for the console to ask the player whether to trust the server.
		ConnContext: func(parent context.Context, _ *nethernet.Conn) (context.Context, context.CancelFunc) {
			return context.WithTimeout(parent, 30*time.Second)
		},
	}.Listen(lanSignaling{Signaling: d, log: log.With("src", "signaling"), keepIdentity: opts.keepIdentity})
	if err != nil {
		return fmt.Errorf("listen for NetherNet: %w", err)
	}
	defer l.Close()

	b := &bridge{log: log, geyser: geyserAddr, verify: opts.verify}
	go b.advertise(ctx, d, name, statusEvery)
	go func() {
		<-ctx.Done()
		_ = l.Close()
	}()

	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				log.Info("shutting down")
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go b.handle(ctx, conn.(*nethernet.Conn))
	}
}

// newWebRTCAPI returns a WebRTC API that gathers IPv4 candidates only. With a non-zero port, all
// connections share that single UDP port so that one firewall rule covers them.
func newWebRTCAPI(port int) (*webrtc.API, func(), error) {
	var se webrtc.SettingEngine
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	if port == 0 {
		return webrtc.NewAPI(webrtc.WithSettingEngine(se)), func() {}, nil
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		return nil, nil, fmt.Errorf("listen for ICE on UDP port %d: %w", port, err)
	}
	mux := webrtc.NewICEUDPMux(nil, conn)
	se.SetICEUDPMux(mux)
	return webrtc.NewAPI(webrtc.WithSettingEngine(se)), func() { _ = mux.Close() }, nil
}
