# mutiny-web (proof of concept)

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

### mkcert

https://github.com/FiloSottile/mkcert

### chromedriver (for tests)

https://chromedriver.chromium.org/

```
brew install chromedriver
```

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

## With SSL

Since we plan to use web workers and other SSL-required things, we can also do SSL in localhost to make testing a little less gotch-ey.

First generate the local cert (requires `mkcert` command):

```
just cert
```

Then start react with SSL flags:

```
npm run start-ssl
```

### PWA

To test out PWA stuff you need to `build` and then run the built artifact:

```
npm run build
```

(if you don't have a server installed: `npm install -g serve`)

Then serve the build folder:

```
serve -s build
```

They recommend running this in an incognito window because caching can be annoying with this stuff. Works for me in Chrome to install Mutiny as a desktop app.

### Docker

Build the websocket-tcp-proxy image

```
DOCKER_BUILDKIT=1 docker build -f Dockerfile-Proxy -t bitcoindevshop/websocket-tcp-proxy .
```

Run the docker image locally
```
docker run -d -p 3001:3001 bitcoindevshop/websocket-tcp-proxy
```

Deploy the docker image:
```
docker tag bitcoindevshop/websocket-tcp-proxy registry.digitalocean.com/bitcoindevshop-do/websocket-tcp-proxy
docker push registry.digitalocean.com/bitcoindevshop-do/websocket-tcp-proxy
```
