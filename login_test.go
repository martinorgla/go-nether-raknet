package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"regexp"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
)

// TestResignLoginKeepsIntegerTimestamps checks that timestamps survive re-signing as integers, as
// Geyser reads them as longs and fails on numbers in exponent notation.
func TestResignLoginKeepsIntegerTimestamps(t *testing.T) {
	clientKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	bridgeKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	identity := login.IdentityData{XUID: "2535461083981792", DisplayName: "Kid", Identity: uuid.NewString()}
	request := login.EncodeOffline(identity, testClientData(), clientKey, false)

	resigned, p, err := resignLogin(context.Background(), unverifiedTokens{}, request, bridgeKey)
	if err != nil {
		t.Fatal(err)
	}
	if p.xuid != identity.XUID || p.name != identity.DisplayName {
		t.Fatalf("unexpected player %+v", p)
	}
	req, clientData, err := splitRequest(resigned)
	if err != nil {
		t.Fatal(err)
	}
	if req.AuthenticationType != authTypeSelfSigned || req.Token == "" {
		t.Fatalf("unexpected request %+v", req)
	}
	sig, err := jose.ParseSigned(req.Token, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := sig.Verify(&bridgeKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`:-?\d+(\.\d+)?[eE]`).Match(payload) || !regexp.MustCompile(`"exp":\d+[,}]`).Match(payload) {
		t.Fatalf("token claims contain exponent notation: %s", payload)
	}
	cd, err := jose.ParseSigned(clientData, []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cd.Verify(&bridgeKey.PublicKey); err != nil {
		t.Fatalf("client data not signed by bridge key: %v", err)
	}
}
