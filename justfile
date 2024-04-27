pack:
    wasm-pack build ./mutiny-wasm --dev --weak-refs --target web --scope mutinywallet

link:
    wasm-pack build ./mutiny-wasm --dev --weak-refs --target web --scope mutinywallet && cd mutiny-wasm/pkg && pnpm link --global

login:
    wasm-pack login --scope=@mutinywallet

dev: 
    wasm-pack build ./mutiny-wasm --weak-refs --target web --scope mutinywallet -- --features console_error_panic_hook

release:
    wasm-pack build ./mutiny-wasm --release --weak-refs --target web --scope mutinywallet

publish:
    wasm-pack publish --access public -t web

[macos]
test:
    cargo test -p mutiny-core --target=aarch64-apple-darwin
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --chrome ./mutiny-core
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --chrome ./mutiny-wasm

[linux]
test:
    cargo test -p mutiny-core --target=x86_64-unknown-linux-gnu
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --firefox ./mutiny-core
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --firefox ./mutiny-wasm

test-nix:
    cargo test -p mutiny-core --target=aarch64-unknown-linux-gnu
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --firefox ./mutiny-core
    WASM_BINDGEN_TEST_TIMEOUT=120 wasm-pack test --headless --firefox ./mutiny-wasm

[macos]
clippy:
    cargo clippy --all-features --tests --package mutiny-core --target=wasm32-unknown-unknown -- -D warnings
    cargo clippy --all-features --tests --package mutiny-core --target=aarch64-apple-darwin -- -D warnings
    cargo clippy --all-features --tests --package mutiny-wasm -- -D warnings

[linux]
clippy:
    cargo clippy --all-features --tests --package mutiny-core --target=wasm32-unknown-unknown -- -D warnings
    cargo clippy --all-features --tests --package mutiny-core --target=x86_64-unknown-linux-gnu -- -D warnings
    cargo clippy --all-features --tests --package mutiny-wasm -- -D warnings

clippy-nix:
    cargo clippy --all-features --tests --package mutiny-core --target=wasm32-unknown-unknown -- -D warnings
    cargo clippy --all-features --tests --package mutiny-core --target=aarch64-unknown-linux-gnu -- -D warnings
    cargo clippy --all-features --tests --package mutiny-wasm -- -D warnings

test-integration test_filter="" run_params="":
    cd integration_tests && cargo test {{test_filter}} -- --test-threads=1 {{run_params}}
