.PHONY: build test run lint fmt docker clean

build:
	cargo build

test:
	cargo test

run:
	cargo run

lint:
	cargo clippy -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

docker:
	docker build -t agentiam .

clean:
	cargo clean
