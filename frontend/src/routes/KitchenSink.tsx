import { useEffect, useState } from 'react';
import logo from '../images/mutiny-logo.svg';
import init, { NodeManager, InitOutput } from "node-manager";

function App() {
    const [wasm, setWasm] = useState<InitOutput>();

    const [mnemonic, setMnemonic] = useState("...")

    const [balance, setBalance] = useState("0")

    const [tx, setTx] = useState("")

    const [address, setAddress] = useState("")

    const [nodeManager, setNodeManager] = useState<NodeManager>();

    const [newPubkey, setNewPubkey] = useState("")

    // Send state
    const [txid, setTxid] = useState("...")
    const [amount, setAmount] = useState("")
    const [destinationAddress, setDestinationAddress] = useState("")

    // TODO make proxy configurable
    const [proxyAddress] = useState("ws://127.0.0.1:3001")
    const [connectPeer, setConnectPeer] = useState("")

    function handleAmountChange(e: React.ChangeEvent<HTMLInputElement>) {
        setAmount(e.target.value);
    }

    function handleDestinationAddressChange(e: React.ChangeEvent<HTMLInputElement>) {
        setDestinationAddress(e.target.value);
    }

    function handleConnectPeerChange(e: React.ChangeEvent<HTMLInputElement>) {
        setConnectPeer(e.target.value);
    }

    function handleTxChange(e: React.ChangeEvent<HTMLInputElement>) {
        setTx(e.target.value);
    }

    useEffect(() => {
        // TODO: learn why we init this but don't actually call stuff on it
        init().then((wasmModule) => {
            setWasm(wasmModule)
            setup()
        })
        // eslint-disable-next-line react-hooks/exhaustive-deps
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

    async function send(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            let amount_num = BigInt(amount);
            let dest = destinationAddress.trim();
            // TODO: we can pass a fee here but not gonna bother for now
            let txid = await nodeManager?.send_to_address(dest, amount_num);
            if (txid) {
                setTxid(txid)
                setAmount("")
                setDestinationAddress("")
            }
        } catch (e) {
            console.error(e);
        }
    }

    async function broadcastTx(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.broadcast_transaction(tx);
        } catch (e) {
            console.error(e);
        }
    }

    async function connect_peer(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.connect_to_peer(newPubkey, proxyAddress, connectPeer)
        } catch (e) {
            console.error(e);
        }
    }


    async function new_node() {
        if (nodeManager) {
            let new_node_identity = await nodeManager.new_node()
            if (new_node_identity) {
                setNewPubkey(new_node_identity.pubkey)
            }
        }
    }

    function createNodeManager() {
        // todo enter password
        setNodeManager(new NodeManager("", undefined))
    }

    return (
        <div className="p-8 flex flex-col gap-4">
            <header>
                <img src={logo} className="App-logo" alt="logo" />
            </header>
            <main className='flex flex-col gap-4'>
                <p>Here is the seed phrase for your node manager:</p>
                <pre>
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
                            <button onClick={() => setMnemonic(nodeManager.show_seed())}>Reveal Seed!</button>
                        </p>
                        <p>
                            {`Wallet Balance: ${balance} sats`}
                        </p>
                        <p>
                            <button onClick={async () => sync()}>Sync Wallet</button>
                        </p>
                        <pre>
                            <code>{address}</code>
                        </pre>
                        <p>
                            <button onClick={async () => setAddress(await nodeManager.get_new_address())}>Generate Address!</button>
                        </p>
                        <form onSubmit={send} className="flex flex-col items-start gap-4 my-4">
                            <h2>Goodbye 2 Ur Sats:</h2>
                            <input type="text" placeholder='Destination address' onChange={handleDestinationAddressChange}></input>
                            <input type="text" placeholder='Amount (sats)' onChange={handleAmountChange}></input>
                            <input type="submit" value="Send" />
                            <pre>
                                <code>Txid: {txid}</code>
                            </pre>
                        </form>
                        <form onSubmit={broadcastTx} className="flex flex-col items-start gap-4 my-4">
                            <h2>Broadcast Tx:</h2>
                            <input type="text" placeholder='tx' onChange={handleTxChange}></input>
                            <input type="submit" value="Send" />
                        </form>
                        <pre>
                            <code>{newPubkey}</code>
                        </pre>
                        <p>
                            <button onClick={async () => new_node()}>New Node!</button>
                        </p>
                        {newPubkey &&
                            <form onSubmit={connect_peer} className="flex flex-col items-start gap-4 my-4">
                                <h2>Connect Peer:</h2>
                                <input type="text" placeholder='Peer Connection String' onChange={handleConnectPeerChange}></input>
                                <input type="submit" value="Connect" />
                            </form>
                        }
                    </>
                }
            </main>
        </div>
    );
}

export default App;
