import { useEffect, useState } from 'react';
import logo from './mutiny-logo.svg';
import init, { generate_seed, InitOutput } from "node-manager";

function App() {

  const [wasm, setWasm] = useState<InitOutput>();

  const [privatekey, setPrivatekey] = useState("...")

  useEffect(() => {
    // TODO: learn why we init this but don't actually call stuff on it
    init().then((wasmModule) => {
      setWasm(wasmModule)
    })
  }, [])

  return (
    <div className="p-8 flex flex-col gap-4">
      <header>
        <img src={logo} className="App-logo" alt="logo" />
      </header>
      <main>
        <p>Here's where you put all your money:</p>
        <pre className=''>
          <code>{privatekey}</code>
        </pre>
        <p>
          <button onClick={() => wasm && setPrivatekey(generate_seed())}>Generate!</button>
        </p>
      </main>
    </div>
  );
}

export default App;
