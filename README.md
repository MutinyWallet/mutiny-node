# mutiny-node

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/MutinyWallet/mutiny-core/blob/master/LICENSE)
[![mutiny-core on crates.io](https://img.shields.io/crates/v/mutiny-core.svg)](https://crates.io/crates/mutiny-core)
[![mutiny-core on docs.rs](https://docs.rs/mutiny-core/badge.svg)](https://docs.rs/mutiny-core)
[![npm version](https://badge.fury.io/js/@mutinywallet%2Fmutiny-wasm.svg)](https://badge.fury.io/js/@mutinywallet%2Fmutiny-wasm)

The mutiny node that powers the mutiny web frontend.

The frontend for Mutiny Wallet is [here](https://github.com/MutinyWallet/mutiny-web).

## Importing

The web front end imports the NPM package that this project
creates [here](https://www.npmjs.com/package/@mutinywallet/mutiny-wasm).

## Development

### Nixos

A `flake.nix` file has been added for easier nix development and testing. Pretty much all cargo / wasm commands work,
though right now optimized for `aarch64-unknown-linux-gnu` and `wasm32-unknown-unknown` compilation in the nix shell.

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

- [rust](https://www.rust-lang.org/) (specifically, nightly: `rustup toolchain install nightly-2023-10-24`
  and `rustup target add wasm32-unknown-unknown --toolchain nightly`)

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

### Testing

To run the local tests you can simply use

```
just test
```

To test running mutiny with [mutiny-web](https://github.com/MutinyWallet/mutiny-web) you'll need to run the following:

```
just pack
just link
```

Then in the mutiny-web repo:

```
just local
```

Then you can run the mutiny-web project and it will use the locally built mutiny-node instead of the published npm
package.

You only need to run `just link` once, but you'll need to run `just pack` every time you make changes to the rust code.
`just link` creates a symlink in the `mutiny-web` project to the `mutiny-node` project. This allows you to make changes
to the `mutiny-node` project and see them reflected in the `mutiny-web` project without having to publish the npm
package. `just pack` builds the wasm binary and needs to be run every time you make changes to the rust code.

### Publishing

The `mutiny-core` rust library and `mutiny-wasm` typescript packages are published when new github releases are created.
Just bump both of those cargo.toml package numbers
and [create release](https://github.com/MutinyWallet/mutiny-node/releases/new)
just publish.
