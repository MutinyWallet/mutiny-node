import { useEffect, useState } from 'react';
import logo from './mutiny-logo.svg';
import init, { NodeManager, InitOutput } from "node-manager";

function App() {

  const [wasm, setWasm] = useState<InitOutput>();

  const [mnemonic, setMnemonic] = useState("...")

  let myNodeManager = {} as NodeManager

  useEffect(() => {
    // TODO: learn why we init this but don't actually call stuff on it
    init().then((wasmModule) => {
      setWasm(wasmModule)
    })
  }, [])

  function createNodeManager() {
    myNodeManager = new NodeManager(undefined)
  }

  return (
    <div className="p-8 flex flex-col gap-4">
      <header>
        <img src={logo} className="App-logo" alt="logo" />
      </header>
      <main>
        <p>Here is the seed phrase for your node manager:</p>
        <pre className=''>
          <code>{mnemonic}</code>
        </pre>
        <p>
          <button onClick={() => wasm && createNodeManager()}>Create the node manager!</button>
        </p>
        <p>
          <button onClick={() => wasm && setMnemonic(myNodeManager.show_seed())}>Reveal Seed!</button>
        </p>
      </main>
    </div>
  );
}

export default App;
