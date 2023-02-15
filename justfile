pack:
    wasm-pack build ./node-manager --dev --target web --scope mutinywallet

pack-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build ./node-manager --dev --target web --scope mutinywallet

login:
    wasm-pack login --scope=@mutinywallet

login-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack login --scope=@mutinywallet

release:
    wasm-pack build --release --target web --scope mutinywallet

release-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build --release --target web --scope mutinywallet

publish:
    wasm-pack publish --access public -t web

publish-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack publish --access public -t web

test:
    wasm-pack test --headless --chrome ./node-manager

test-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack test --headless --chrome ./node-manager

clippy:
    cargo clippy --package node-manager -- -Aclippy::drop_non_drop

clippy-mac:
    cd ./node-manager && AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang cargo clippy --package node-manager -- -Aclippy::drop_non_drop
