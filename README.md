# mutiny-node

The mutiny node that powers the mutiny web frontend.

The original frontend proof of concept has moved to [here](https://github.com/MutinyWallet/mutiny-web-poc). While the latest version is being worked on [here](https://github.com/MutinyWallet/mutiny-web).

## Importing

Both of those current web frontends import the NPM package that this project creates [here](https://www.npmjs.com/package/@mutinywallet/node-manager).


## Development

### Building on the mac

See the discussion here:
https://github.com/rust-bitcoin/rust-secp256k1/issues/283

You may have to either prefix some environment variables or set them in your env or shell file:

```
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang
```

### Dependencies

- [rust](https://www.rust-lang.org/) (specifically, nightly: `rustup toolchain install nightly`)

- [node](https://nodejs.org/en/)

- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/#)

```
cargo install wasm-pack
```

- [just](https://github.com/casey/just)

- [chromedriver](https://chromedriver.chromium.org/)

```
brew install chromedriver
```

### Build

Get all the dependencies above first.

Build the rust wasm stuff:

```
just pack
```

### Websocket proxy

You can use the default websocket proxy @ p.mutinywallet.com no matter what network you are on. To run it locally, follow the docker instructions [here](https://github.com/Mutiny-Wallet/ln-websocket-proxy).

### Bitcoin networks

You'll need a regtest bitcoin node, electrs, and an exposed port to whatever regtest node you are connecting to.

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

### Publishing

Right now publishing is manual. 

First change the version of node-manager in `./node-manager/Cargo.toml`.

```
just login
just release
just publish
```
