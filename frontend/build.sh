# Reference: https://betterprogramming.pub/deploying-a-wasm-powered-react-app-on-vercel-cf3cae2a75d6

echo "Installing Rustup..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Adding binaries to path
source "$HOME/.cargo/env"

echo "Installing wasm-pack..."
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh -s -- -y

echo "Installing a recent version of clang"
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add - || exit 1
sudo apt-add-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-10 main" || exit 1
sudo apt-get update || exit 1
sudo apt-get install -y libclang-common-10-dev clang-10 libc6-dev-i386 || exit 1

echo "Building node-manager..."
npm run build:wasm

echo "Build static frontend client..."
npm run build