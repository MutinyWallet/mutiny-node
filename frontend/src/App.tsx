import { useEffect, useState } from 'react';
import logo from './mutiny-logo.svg';
import init, { NodeManager, InitOutput } from "node-manager";

function App() {

  const [wasm, setWasm] = useState<InitOutput>();

  const [mnemonic, setMnemonic] = useState("...")

  const [balance, setBalance] = useState("0")

  const [address, setAddress] = useState("")

  const [nodeManager, setNodeManager] = useState<NodeManager>();

  useEffect(() => {
    // TODO: learn why we init this but don't actually call stuff on it
    init().then((wasmModule) => {
      setWasm(wasmModule)
      setup()
    })
  }, [])

  async function setup() {
    if (NodeManager.has_node_manager()) {
      createNodeManager()
      let balance = await nodeManager?.get_wallet_balance()
      if (balance) {
        setBalance(balance.toLocaleString())
      }
    }
  }

  async function sync() {
    if (nodeManager) {
      await nodeManager.sync()
      let balance = await nodeManager.get_wallet_balance()
      if (balance) {
        setBalance(balance.toLocaleString())
      }
    }
  }

  function createNodeManager() {
    setNodeManager(new NodeManager(undefined))
  }

  return (
    <div className="p-8 flex flex-col gap-4">
      <header>
        <img src={logo} className="App-logo" alt="logo" />
      </header>
      <main className='flex flex-col gap-4'>
        <p>Here is the seed phrase for your node manager:</p>
        <pre className=''>
          <code>{mnemonic}</code>
        </pre>
        {!nodeManager &&
          <p>
            <button onClick={() => wasm && createNodeManager()}>Create the node manager!</button>
          </p>
        }
        {nodeManager &&
          <>
            <p>
              {`Wallet Balance: ${balance} sats`}
            </p>
            <pre className=''>
                <code>{address}</code>
            </pre>
            <p>
              <button onClick={() => setMnemonic(nodeManager.show_seed())}>Reveal Seed!</button>
            </p>
            <p>
              <button onClick={async () => setAddress(await nodeManager.get_new_address())}>Generate Address!</button>
            </p>
            <p>
              <button onClick={async () => sync()}>Sync Wallet</button>
            </p>
            <p>
              <button onClick={() => nodeManager.test_ws()}>Test Websockets</button>
            </p>

          </>
        }
      </main>
    </div>
  );
}

export default App;
