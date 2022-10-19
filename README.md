# mutiny-web

mutiny, but for the web!

## resources

https://github.com/thunderbiscuit/bitcoin-wasm-react

https://prestonrichey.com/blog/react-rust-wasm/

https://tkat0.github.io/posts/how-to-create-a-react-app-with-rust-and-wasm

https://github.com/benthecarman/wasm-rust-demo

## building on the mac

See the discussion here:
https://github.com/rust-bitcoin/rust-secp256k1/issues/283

I installed llvm, and then use `just pack-mac` instead of `just pack` (so that wasm-pack will use the homebrew installed version of llvm stuff, instead of the system default)

## dependencies

### rust

https://www.rust-lang.org/

### node (npm)

https://nodejs.org/en/

### wasm-pack

https://rustwasm.github.io/wasm-pack/installer/#

```
cargo install wasm-pack
```

### just (not really required but I like it)

https://github.com/casey/just

## Build

Get all the dependencies above first.

Build the rust wasm stuff:
```
just pack
```

or on mac:
```
just pack-mac
```

do the frontend things:
```
cd frontend
npm i
npm start
```

