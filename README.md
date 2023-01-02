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

### Regtest development

You'll need a regtest bitcoin node, electrs, and an exposed port to whatever regtest node you are connecting to.

#### For Testnet / Mainnet mutiny

Mutiny defaults to regtest, but the network can be set by environment variable (it's set to "bitcoin" in the production deployment).

Create a `.env.local` file in the frontend dir and add this:

```
REACT_APP_NETWORK="testnet"
```

Or

```
REACT_APP_NETWORK="bitcoin"
```

Then restart your dev server.

#### For [electrs](https://github.com/Blockstream/electrs)

First build it, then run this script for regtest, replacing paths and passwords where necessary. YMMV. One special note is that this is for cookie password based auth.

```
/path/to/target/release/electrs -vvvv --daemon-dir /path/to/.bitcoin/regtest/data/ --timestamp --blocks-dir /path/to/.bitcoin/regtest/data/regtest/blocks/ --cookie="bitcoinrpc:{cookiebasedpassword}" --db-dir /path/to/.electrs/ --network regtest --http-addr 0.0.0.0:3003
```

#### Expose lightning node regtest

I use bore for this. Swap out 9735 with whatever your OTHER node's port is running on. Typically 9735.

```
bore local 9735 --to bore.pub
```

Whenever you are wanting to connect to this node from the webbrowser, put our default websocket proxy url into it along with the following for the pubkey connect string.

You'll want the pubkey you're connecting to, the IP address of bore (this could change but hasn't changed for me yet), and the port that bore returns that always changes, so look at the bore logs.

```
{other_node_pubkey}@159.223.171.199:{port_returned_from_bore}
```
