package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

// authTypeSelfSigned is the AuthenticationType of a login request carrying a self-signed token.
const authTypeSelfSigned = 2

// tokenVerifier verifies the multiplayer token of a login request and returns its claims.
type tokenVerifier interface {
	Verify(ctx context.Context, token string) (map[string]any, error)
}

// xboxVerifier verifies multiplayer tokens issued by Minecraft's authorization service. The OIDC
// configuration is fetched on first use and retried on later logins if that fails.
type xboxVerifier struct {
	mu  sync.Mutex
	env *service.AuthorizationEnvironment
}

func (v *xboxVerifier) Verify(ctx context.Context, token string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	v.mu.Lock()
	if v.env == nil {
		d, err := service.Discover(ctx, service.ApplicationTypeMinecraftPE, protocol.CurrentVersion)
		if err != nil {
			v.mu.Unlock()
			return nil, fmt.Errorf("discover Minecraft services: %w", err)
		}
		env := new(service.AuthorizationEnvironment)
		if err := d.Environment(env); err != nil {
			v.mu.Unlock()
			return nil, fmt.Errorf("decode authorization environment: %w", err)
		}
		v.env = env
	}
	env := v.env
	v.mu.Unlock()

	verifier, err := env.VerifierContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("create token verifier: %w", err)
	}
	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	var payload json.RawMessage
	if err := idt.Claims(&payload); err != nil {
		return nil, fmt.Errorf("read token claims: %w", err)
	}
	return decodeClaims(payload)
}

// decodeClaims decodes JWT claims, keeping numbers as json.Number so that they are written back
// exactly as they were. Geyser fails on timestamps written in exponent notation.
func decodeClaims(payload []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	claims := make(map[string]any)
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("decode token claims: %w", err)
	}
	return claims, nil
}

// player identifies the player of a verified login request.
type player struct {
	name string
	xuid string
}

// connectionRequest is the JSON part of the ConnectionRequest field of a Login packet.
type connectionRequest struct {
	AuthenticationType uint8  `json:"AuthenticationType"`
	Certificate        string `json:"Certificate"`
	Token              string `json:"Token"`
}

// resignLogin verifies the connection request of a console and returns an equivalent request signed
// with key. The console's token must be issued by Minecraft's authorization service for the key that
// signed its client data. The new request carries the same token claims and client data, self-signed
// with key, so that Geyser derives the same player identity and runs the encryption handshake
// against key, which the bridge holds.
func resignLogin(ctx context.Context, v tokenVerifier, request []byte, key *ecdsa.PrivateKey) ([]byte, player, error) {
	req, clientData, err := splitRequest(request)
	if err != nil {
		return nil, player{}, err
	}
	if req.Token == "" {
		return nil, player{}, errors.New("login has no multiplayer token: the console is not signed in to Xbox Live")
	}
	claims, err := v.Verify(ctx, req.Token)
	if err != nil {
		return nil, player{}, fmt.Errorf("verify multiplayer token: %w", err)
	}
	p := player{}
	p.name, _ = claims["xname"].(string)
	p.xuid, _ = claims["xid"].(string)
	if p.xuid == "" {
		return nil, player{}, errors.New("multiplayer token has no XUID")
	}
	cpk, _ := claims["cpk"].(string)
	clientKey := new(ecdsa.PublicKey)
	if err := login.ParsePublicKey(cpk, clientKey); err != nil {
		return nil, player{}, fmt.Errorf("parse token key: %w", err)
	}
	cd, err := jose.ParseSigned(clientData, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return nil, player{}, fmt.Errorf("parse client data: %w", err)
	}
	clientDataPayload, err := cd.Verify(clientKey)
	if err != nil {
		return nil, player{}, fmt.Errorf("client data is not signed by the token key: %w", err)
	}

	keyData := login.MarshalPublicKey(&key.PublicKey)
	signer, err := jose.NewSigner(jose.SigningKey{Key: key, Algorithm: jose.ES384}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]any{"x5u": keyData},
	})
	if err != nil {
		return nil, player{}, err
	}
	claims["cpk"] = keyData
	// The claims are encoded with encoding/json rather than through go-jose's JWT helpers, which write
	// large numbers such as timestamps in exponent notation.
	tokenPayload, err := json.Marshal(claims)
	if err != nil {
		return nil, player{}, fmt.Errorf("encode token claims: %w", err)
	}
	token, err := sign(signer, tokenPayload)
	if err != nil {
		return nil, player{}, fmt.Errorf("sign token: %w", err)
	}
	signedClientData, err := sign(signer, clientDataPayload)
	if err != nil {
		return nil, player{}, fmt.Errorf("sign client data: %w", err)
	}
	return joinRequest(connectionRequest{AuthenticationType: authTypeSelfSigned, Token: token}, signedClientData), p, nil
}

func sign(signer jose.Signer, payload []byte) (string, error) {
	sig, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return sig.CompactSerialize()
}

// splitRequest splits a connection request into its JSON part and the client data JWT. Both are
// prefixed with their length as a little-endian int32.
func splitRequest(b []byte) (connectionRequest, string, error) {
	var req connectionRequest
	r := bytes.NewReader(b)
	readPart := func() ([]byte, error) {
		var n int32
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return nil, err
		}
		if n < 0 || int(n) > r.Len() {
			return nil, fmt.Errorf("invalid length %d", n)
		}
		part := make([]byte, n)
		_, err := r.Read(part)
		return part, err
	}
	reqJSON, err := readPart()
	if err != nil {
		return req, "", fmt.Errorf("read request: %w", err)
	}
	if err := json.Unmarshal(reqJSON, &req); err != nil {
		return req, "", fmt.Errorf("decode request: %w", err)
	}
	clientData, err := readPart()
	if err != nil {
		return req, "", fmt.Errorf("read client data: %w", err)
	}
	return req, string(clientData), nil
}

// joinRequest is the inverse of splitRequest.
func joinRequest(req connectionRequest, clientData string) []byte {
	reqJSON, _ := json.Marshal(req)
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, int32(len(reqJSON)))
	buf.Write(reqJSON)
	_ = binary.Write(buf, binary.LittleEndian, int32(len(clientData)))
	buf.WriteString(clientData)
	return buf.Bytes()
}
