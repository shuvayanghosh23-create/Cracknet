.PHONY: build clean test run

build:
	cargo build --release
	go build -o cracknet ./cmd/main.go

test:
	cargo test
	go test ./...

clean:
	cargo clean
	rm -f cracknet

run:
	go run ./cmd/main.go
