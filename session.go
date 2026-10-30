package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"github.com/df-mc/go-nethernet"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

// session relays one console to Geyser.
//
// NetherNet runs over DTLS and carries no Minecraft encryption, while Geyser encrypts RakNet sessions
// with a key derived from the player's login key, which only the console holds. The session therefore
// logs in to Geyser itself: it verifies the console's login, re-signs it with its own key, completes
// the encryption handshake with Geyser and from then on decrypts and encrypts the Geyser side.
// Packets are otherwise forwarded without being decoded.
type session struct {
	log    *slog.Logger
	verify tokenVerifier
	key    *ecdsa.PrivateKey

	client     *nethernet.Conn
	clientEnc  *packet.Encoder
	clientDec  *packet.Decoder
	server     *raknet.Conn
	serverEnc  *packet.Encoder
	serverDec  *packet.Decoder
	compressed bool
}

func newSession(log *slog.Logger, verify tokenVerifier, client *nethernet.Conn, server *raknet.Conn) (*session, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	s := &session{
		log:       log,
		verify:    verify,
		key:       key,
		client:    client,
		clientEnc: packet.NewEncoder(client),
		clientDec: packet.NewDecoder(newClientReader(client)),
		server:    server,
		serverEnc: packet.NewEncoder(server),
		serverDec: packet.NewDecoder(server),
	}
	s.serverDec.DisableBatchPacketLimit()
	return s, nil
}

// login runs the login sequence up to the point where Geyser has enabled encryption.
func (s *session) login(ctx context.Context) error {
	// RequestNetworkSettings: console -> Geyser.
	if err := s.forwardUntil(s.clientDec, s.serverEnc, packet.IDRequestNetworkSettings, nil); err != nil {
		return fmt.Errorf("wait for RequestNetworkSettings: %w", err)
	}
	// NetworkSettings: Geyser -> console. Compression starts on both sides after it.
	err := s.forwardUntil(s.serverDec, s.clientEnc, packet.IDNetworkSettings, func(pk []byte) error {
		settings := &packet.NetworkSettings{}
		if err := unmarshal(pk, settings); err != nil {
			return err
		}
		compression, ok := packet.CompressionByID(settings.CompressionAlgorithm)
		if !ok {
			return fmt.Errorf("unknown compression algorithm %d", settings.CompressionAlgorithm)
		}
		if err := s.clientEnc.Encode([][]byte{pk}); err != nil {
			return err
		}
		threshold := int(settings.CompressionThreshold)
		s.clientEnc.EnableCompression(compression, threshold)
		s.clientDec.EnableCompression(compression, 0)
		s.serverEnc.EnableCompression(compression, threshold)
		s.serverDec.EnableCompression(compression, -1)
		s.compressed = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("wait for NetworkSettings: %w", err)
	}
	// Login: console -> Geyser, re-signed by the bridge.
	err = s.forwardUntil(s.clientDec, s.serverEnc, packet.IDLogin, func(pk []byte) error {
		loginPk := &packet.Login{}
		if err := unmarshal(pk, loginPk); err != nil {
			return err
		}
		request, p, err := resignLogin(ctx, s.verify, loginPk.ConnectionRequest, s.key)
		if err != nil {
			_ = s.disconnectClient("disconnectionScreen.notAuthenticated")
			return err
		}
		s.log.Info("player logged in", "name", p.name, "xuid", p.xuid)
		loginPk.ConnectionRequest = request
		return s.serverEnc.Encode([][]byte{marshal(loginPk)})
	})
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	// ServerToClientHandshake: answered by the bridge, never reaches the console.
	err = s.forwardUntil(s.serverDec, s.clientEnc, packet.IDServerToClientHandshake, func(pk []byte) error {
		handshake := &packet.ServerToClientHandshake{}
		if err := unmarshal(pk, handshake); err != nil {
			return err
		}
		keyBytes, err := s.encryptionKey(string(handshake.JWT))
		if err != nil {
			return err
		}
		s.serverEnc.EnableEncryption(keyBytes)
		s.serverDec.EnableEncryption(keyBytes)
		return s.serverEnc.Encode([][]byte{marshal(&packet.ClientToServerHandshake{})})
	})
	if err != nil {
		return fmt.Errorf("encryption handshake: %w", err)
	}
	return nil
}

// forwardUntil forwards packets from dec to enc until a packet with the ID passed arrives. That packet
// is passed to handle instead, or forwarded as well if handle is nil. A Disconnect from either side
// is forwarded and ends the login.
func (s *session) forwardUntil(dec *packet.Decoder, enc *packet.Encoder, id uint32, handle func(pk []byte) error) error {
	for {
		pks, err := dec.Decode()
		if err != nil {
			return err
		}
		for i, pk := range pks {
			pkID, err := packetID(pk)
			if err != nil {
				return err
			}
			switch pkID {
			case id:
				if err := encode(enc, pks[:i]); err != nil {
					return err
				}
				if handle == nil {
					return encode(enc, pks[i:])
				}
				if err := handle(pk); err != nil {
					return err
				}
				return encode(enc, pks[i+1:])
			case packet.IDDisconnect:
				_ = encode(enc, pks)
				return errors.New("disconnected during login")
			}
		}
		if err := encode(enc, pks); err != nil {
			return err
		}
	}
}

// encode writes pks as one batch unless there are none, as an empty batch is not valid.
func encode(enc *packet.Encoder, pks [][]byte) error {
	if len(pks) == 0 {
		return nil
	}
	return enc.Encode(pks)
}

// encryptionKey derives the key Geyser enables encryption with from its handshake JWT.
func (s *session) encryptionKey(handshake string) ([32]byte, error) {
	tok, err := jwt.ParseSigned(handshake, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return [32]byte{}, fmt.Errorf("parse handshake: %w", err)
	}
	x5u, _ := tok.Headers[0].ExtraHeaders["x5u"].(string)
	serverKey := new(ecdsa.PublicKey)
	if err := login.ParsePublicKey(x5u, serverKey); err != nil {
		return [32]byte{}, fmt.Errorf("parse server key: %w", err)
	}
	var claims struct {
		Salt string `json:"salt"`
	}
	if err := tok.Claims(serverKey, &claims); err != nil {
		return [32]byte{}, fmt.Errorf("verify handshake: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(claims.Salt, "="))
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode salt: %w", err)
	}
	priv, err := s.key.ECDH()
	if err != nil {
		return [32]byte{}, err
	}
	pub, err := serverKey.ECDH()
	if err != nil {
		return [32]byte{}, err
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(append(salt, secret...)), nil
}

// relay forwards packets in both directions until either side closes.
func (s *session) relay(ctx context.Context) {
	done := make(chan struct{}, 2)
	pipe := func(name string, dec *packet.Decoder, enc *packet.Encoder) {
		defer func() { done <- struct{}{} }()
		for {
			pks, err := dec.Decode()
			if err != nil {
				logClosed(s.log, "read from "+name, err)
				return
			}
			if err := encode(enc, pks); err != nil {
				logClosed(s.log, "forward from "+name, err)
				return
			}
		}
	}
	go pipe("client", s.clientDec, s.serverEnc)
	go pipe("Geyser", s.serverDec, s.clientEnc)
	select {
	case <-done:
	case <-ctx.Done():
	}
}

// disconnectClient shows the console a disconnect screen with the message passed.
func (s *session) disconnectClient(message string) error {
	return s.clientEnc.Encode([][]byte{marshal(&packet.Disconnect{Message: message})})
}

func packetID(pk []byte) (uint32, error) {
	var h packet.Header
	if err := h.Read(bytes.NewBuffer(pk)); err != nil {
		return 0, fmt.Errorf("read packet header: %w", err)
	}
	return h.PacketID, nil
}

func unmarshal(pk []byte, p packet.Packet) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("decode packet %T: %v", p, r)
		}
	}()
	buf := bytes.NewBuffer(pk)
	var h packet.Header
	if err := h.Read(buf); err != nil {
		return err
	}
	p.Marshal(protocol.NewReader(buf, 0, false))
	return nil
}

func marshal(p packet.Packet) []byte {
	buf := new(bytes.Buffer)
	h := packet.Header{PacketID: p.ID()}
	_ = h.Write(buf)
	p.Marshal(protocol.NewWriter(buf, 0))
	return buf.Bytes()
}

// clientReader merges the reliable and unreliable data channels of a console into one packet stream
// for a packet.Decoder.
type clientReader struct {
	conn    *nethernet.Conn
	packets chan []byte
}

func newClientReader(conn *nethernet.Conn) *clientReader {
	r := &clientReader{conn: conn, packets: make(chan []byte)}
	for _, rel := range []nethernet.MessageReliability{nethernet.MessageReliabilityReliable, nethernet.MessageReliabilityUnreliable} {
		go func() {
			for {
				pk, err := conn.Receive(rel)
				if err != nil {
					return
				}
				select {
				case r.packets <- pk:
				case <-conn.Context().Done():
					return
				}
			}
		}()
	}
	return r
}

func (r *clientReader) ReadPacket() ([]byte, error) {
	select {
	case pk := <-r.packets:
		return pk, nil
	case <-r.conn.Context().Done():
		return nil, errors.Join(context.Cause(r.conn.Context()), net.ErrClosed)
	}
}

func (r *clientReader) Read([]byte) (int, error) { return 0, io.ErrNoProgress }

// BatchHeader reports that NetherNet batches have no header.
func (r *clientReader) BatchHeader() []byte { return nil }

// DisableEncryption reports that NetherNet batches are never encrypted.
func (r *clientReader) DisableEncryption() bool { return true }
