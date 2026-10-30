BINARY := nether-bridge

.PHONY: build pi test clean

build:
	go build -o dist/$(BINARY) .

# Raspberry Pi 3/4/5 with a 64-bit OS.
pi:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dist/$(BINARY)-linux-arm64 .

test:
	go test -race ./...

clean:
	rm -rf dist
