# mutiny-node

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/MutinyWallet/mutiny-core/blob/master/LICENSE)
[![mutiny-core on crates.io](https://img.shields.io/crates/v/mutiny-core.svg)](https://crates.io/crates/mutiny-core)
[![mutiny-core on docs.rs](https://docs.rs/mutiny-core/badge.svg)](https://docs.rs/mutiny-core)
[![npm version](https://badge.fury.io/js/@mutinywallet%2Fmutiny-wasm.svg)](https://badge.fury.io/js/@mutinywallet%2Fmutiny-wasm)

The mutiny node that powers the mutiny web frontend.

The original frontend proof of concept has moved to [here](https://github.com/MutinyWallet/mutiny-web-poc). While the latest version is being worked on [here](https://github.com/MutinyWallet/mutiny-web).

## Importing

Both of those current web frontends import the NPM package that this project creates [here](https://www.npmjs.com/package/@mutinywallet/node-manager).


## Development

### Nixos

A `flake.nix` file has been added for easier nix development and testing. Pretty much all cargo / wasm commands work, though right now optimized for `aarch64-unknown-linux-gnu` and `wasm32-unknown-unknown` compilation in the nix shell. 

To start:
```
nix develop
```

Then the following `just` examples that work:

```
just clippy-nix
just test-nix
just pack
just release
```

### Building on the mac

See the discussion here:
https://github.com/rust-bitcoin/rust-secp256k1/issues/283

You may have to either prefix some environment variables or set them in your env or shell file:

```
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang
```

### Dependencies

- [rust](https://www.rust-lang.org/) (specifically, nightly: `rustup toolchain install nightly` and `rustup target add wasm32-unknown-unknown --toolchain nightly`)

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

The `mutiny-core` rust library and `mutiny-wasm` typescript packages are published when new github releases are created. Just bump both of those cargo.toml package numbers and [create release](https://github.com/MutinyWallet/mutiny-node/releases/new)
just publish
```
