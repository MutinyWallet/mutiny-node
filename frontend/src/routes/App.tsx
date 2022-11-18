
import logo from '../images/mutiny-logo.svg';
import { useNavigate } from "react-router-dom";
import { useEffect, useState } from 'react';
import ScreenMain from '../components/ScreenMain';
import More from '../components/More';


function App() {
  const [wasmSupported, setWasmSupported] = useState(true)

  let navigate = useNavigate();

  function handleNavSend() {
    navigate("/send")
  }

  // function handleNavDeposit() {
  //   navigate("/deposit")
  // }

  function handleNavReceive() {
    navigate("/receive")

  }

  useEffect(() => {
    // https://stackoverflow.com/questions/47879864/how-can-i-check-if-a-browser-supports-webassembly
    const checkWasm = async () => {
      try {
        if (typeof WebAssembly === "object"
          && typeof WebAssembly.instantiate === "function") {
          const module = new WebAssembly.Module(Uint8Array.of(0x0, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00));
          if (!(module instanceof WebAssembly.Module)) {
            throw new Error("Couldn't instantiate WASM Module")
          }
        } else {
          throw new Error("No WebAssembly global object found")
        }
      } catch (e) {
        console.error(e)
        setWasmSupported(false);
      }
    }
    checkWasm();

  }, [])

  return (
    <div className="flex flex-col h-full fixed w-full">
      <header className='p-8'>
        <img src={logo} className="App-logo" alt="logo" />
        <h2>You're probably looking for <a href="/tests">the tests</a></h2>
        <p>View the <a href="https://github.com/BitcoinDevShop/mutiny-web-poc">source</a></p>
        {wasmSupported ? <p>WASM works!</p> :
          <p>
            WASM does not seem supported in your browser, this might not work for you!
            You may have to turn on Javascript JIT in your browser settings.
          </p>
        }
      </header>
      <ScreenMain>
        <div />
        <h1 className='text-4xl font-light uppercase'>69_420 <span className='text-2xl'>sats</span></h1>
        <div />

        <div className='flex flex-col gap-2 items-start'>
          <button className='green-button' onClick={handleNavSend}>Send</button>
          {/* TODO if no funds can do deposit instead of receive */}
          {/* <button className='blue-button' onClick={handleNavDeposit}>Deposit</button> */}
          <div className='w-full flex justify-between items-center'>
            <button className='blue-button' onClick={handleNavReceive}>Receive</button>
            <More />
          </div>
        </div>
      </ScreenMain>
    </div>
  );
}

export default App;
