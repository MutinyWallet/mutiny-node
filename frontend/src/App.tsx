import { useEffect, useState } from 'react';
import logo from './logo.svg';
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
    <div className="p-8">
      <header className="App-header">
        <p>Here's where you put all your money:</p>
        <pre className='bg-gray-100 border rounded shadow-lg p-4 m-4'>
          <code>{privatekey}</code>
        </pre>
        <p>
          <button onClick={() => wasm && setPrivatekey(generate_seed())}>Generate!</button>
        </p>
      </header>
    </div>
  );
}

export default App;
