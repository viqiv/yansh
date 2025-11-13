run: build
	./target/debug/shell


build:
	cargo rustc -- -C link-arg=-nostartfiles -lc
