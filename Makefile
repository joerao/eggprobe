.PHONY: build run test smoke release-linux clean
build:
	cargo build --release
run: build
	./target/release/eggprobe
test:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo test
	python3 scripts/test_installer.py
# Scans only loopback, so it is safe anywhere and needs no network.
smoke: build
	./target/release/eggprobe --scan --subnet 127.0.0.1/32 --skip mdns --skip tailnet-probe | python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["complete"], r'
# Static Linux archives in dist/; needs cargo-zigbuild and zig.
release-linux:
	scripts/build-release.sh dev linux
	scripts/build-release.sh dev checksums
clean:
	cargo clean
	rm -rf dist
