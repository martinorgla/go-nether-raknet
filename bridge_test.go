package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/discovery"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// unverifiedTokens accepts any multiplayer token, standing in for Minecraft's authorization service.
type unverifiedTokens struct{}

func (unverifiedTokens) Verify(_ context.Context, token string) (map[string]any, error) {
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES384, jose.RS256})
	if err != nil {
		return nil, err
	}
	return decodeClaims(sig.UnsafePayloadWithoutVerification())
}

// rejectingTokens rejects every multiplayer token.
type rejectingTokens struct{}

func (rejectingTokens) Verify(context.Context, string) (map[string]any, error) {
	return nil, errors.New("rejected")
}

// TestBridge runs a Bedrock server (standing in for Geyser) on RakNet, the bridge on a local discovery
// listener and a LAN client, and checks that the client finds the world and completes the login
// through the bridge, which handles the encryption handshake with the server.
func TestBridge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	geyser, err := minecraft.ListenConfig{
		AuthenticationDisabled: true,
		StatusProvider:         minecraft.NewStatusProvider("Test MOTD", "Test world"),
	}.Listen("raknet", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer geyser.Close()
	go func() {
		for {
			if _, err := geyser.Accept(); err != nil {
				return
			}
		}
	}()

	networkID, cd := startBridge(t, ctx, log, geyser.Addr().String(), unverifiedTokens{})

	conn, err := nethernet.Dialer{Log: log, AllowIdentitylessServer: true}.DialContext(ctx, strconv.FormatUint(networkID, 10), cd)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pks := clientLogin(t, conn)
	for _, pk := range pks {
		if id, _ := packetID(pk); id == packet.IDPlayStatus {
			status := &packet.PlayStatus{}
			if err := unmarshal(pk, status); err != nil {
				t.Fatal(err)
			}
			if status.Status != packet.PlayStatusLoginSuccess {
				t.Fatalf("play status %d, want login success", status.Status)
			}
			return
		}
	}
	t.Fatalf("no PlayStatus after login, got %d packets", len(pks))
}

// TestBridgeRejectsUnverifiedLogin checks that a login whose token cannot be verified never reaches
// the server.
func TestBridgeRejectsUnverifiedLogin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

	geyser, err := minecraft.ListenConfig{AuthenticationDisabled: true}.Listen("raknet", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer geyser.Close()

	networkID, cd := startBridge(t, ctx, log, geyser.Addr().String(), rejectingTokens{})
	conn, err := nethernet.Dialer{Log: log, AllowIdentitylessServer: true}.DialContext(ctx, strconv.FormatUint(networkID, 10), cd)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	pks := clientLogin(t, conn)
	if len(pks) != 1 {
		t.Fatalf("got %d packets, want a single Disconnect", len(pks))
	}
	if id, _ := packetID(pks[0]); id != packet.IDDisconnect {
		t.Fatalf("got packet %d, want Disconnect", id)
	}
}

// startBridge runs the bridge against the server at geyserAddr and returns the network ID it
// announces together with a discovery listener a client can dial it over.
func startBridge(t *testing.T, ctx context.Context, log *slog.Logger, geyserAddr string, verify tokenVerifier) (uint64, *discovery.Listener) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bridgeAddr := pc.LocalAddr().(*net.UDPAddr)
	_ = pc.Close()
	d, err := discovery.ListenConfig{NetworkID: 42, Log: log}.Listen(bridgeAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })

	pc, err = net.ListenPacket("udp4", ":0")
	if err != nil {
		t.Fatal(err)
	}
	icePort := pc.LocalAddr().(*net.UDPAddr).Port
	_ = pc.Close()
	api, closeAPI, err := newWebRTCAPI(icePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeAPI)
	go func() {
		_ = serve(ctx, log, d, api, geyserAddr, key, "fallback", 200*time.Millisecond, lanOptions{verify: verify})
	}()

	// LAN client, broadcasting straight to the bridge.
	cd, err := discovery.ListenConfig{NetworkID: 7, BroadcastAddress: bridgeAddr, Log: log}.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cd.Close() })

	var data discovery.ServerData
	for {
		select {
		case <-ctx.Done():
			t.Fatalf("world not discovered, last data: %+v", data)
		case <-time.After(500 * time.Millisecond):
		}
		for id, b := range cd.Responses() {
			if err := data.UnmarshalBinary(b); err != nil {
				t.Fatal(err)
			}
			if data.ServerName == "fallback" {
				continue // Geyser has not been pinged yet.
			}
			if data.Version != protocol.CurrentVersion || data.Protocol != protocol.CurrentProtocol || data.ConnectionType != 4 {
				t.Fatalf("unexpected server data: %+v", data)
			}
			return id, cd
		}
	}
}

// clientLogin logs in over conn like a console does and returns the packets of the first batch the
// bridge sends after the login.
func clientLogin(t *testing.T, conn *nethernet.Conn) [][]byte {
	t.Helper()
	enc, dec := packet.NewEncoder(conn), packet.NewDecoder(conn)

	if err := enc.Encode([][]byte{marshal(&packet.RequestNetworkSettings{ClientProtocol: protocol.CurrentProtocol})}); err != nil {
		t.Fatal(err)
	}
	pks, err := dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	settings := &packet.NetworkSettings{}
	if err := unmarshal(pks[0], settings); err != nil {
		t.Fatal(err)
	}
	compression, _ := packet.CompressionByID(settings.CompressionAlgorithm)
	enc.EnableCompression(compression, int(settings.CompressionThreshold))
	dec.EnableCompression(compression, 0)

	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	identity := login.IdentityData{XUID: "2535400000000001", DisplayName: "Kid", Identity: uuid.NewString()}
	request := login.EncodeOffline(identity, testClientData(), key, false)
	if err := enc.Encode([][]byte{marshal(&packet.Login{ClientProtocol: protocol.CurrentProtocol, ConnectionRequest: request})}); err != nil {
		t.Fatal(err)
	}
	pks, err = dec.Decode()
	if err != nil {
		t.Fatal(err)
	}
	return pks
}

func testClientData() login.ClientData {
	return login.ClientData{
		DeviceOS:          protocol.DeviceXBOX,
		DeviceID:          login.DeviceID(uuid.NewString()),
		GameVersion:       protocol.CurrentVersion,
		LanguageCode:      "en_GB",
		ServerAddress:     "127.0.0.1:19132",
		SkinID:            "skin",
		SkinData:          base64.StdEncoding.EncodeToString(make([]byte, 64*64*4)),
		SkinImageWidth:    64,
		SkinImageHeight:   64,
		SkinResourcePatch: base64.StdEncoding.EncodeToString([]byte(`{"geometry":{"default":"geometry.humanoid.custom"}}`)),
		AnimatedImageData: []login.SkinAnimation{},
		PersonaPieces:     []login.PersonaPiece{},
		PieceTintColours:  []login.PersonaPieceTintColour{},
	}
}
