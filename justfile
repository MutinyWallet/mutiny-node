pack:
    wasm-pack build ./node-manager --target web

pack-mac:
    AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang wasm-pack build ./node-manager --target web

cert:
    mkdir -p ./frontend/.cert && mkcert -key-file ./frontend/.cert/key.pem -cert-file ./frontend/.cert/cert.pem "localhost"