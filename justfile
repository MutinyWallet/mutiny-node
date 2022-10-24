pack:
    wasm-pack build ./node-manager --target web

pack-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build ./node-manager --target web

test:
    wasm-pack test --headless --chrome ./node-manager

test-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack test --headless --chrome ./node-manager

cert:
    mkdir -p ./frontend/.cert && mkcert -key-file ./frontend/.cert/key.pem -cert-file ./frontend/.cert/cert.pem "localhost"