import {useContext, useState} from 'react';
import logo from '../images/mutiny-logo.svg';
import {NodeManagerContext} from "@components/GlobalStateProvider";

function App() {
    const [mnemonic, setMnemonic] = useState("...")

    const [feeEstimate, setFeeEstimate] = useState("...")

    const [balance, setBalance] = useState("0")

    const [tx, setTx] = useState("")

    const [address, setAddress] = useState("")

    const [invoice, setInvoice] = useState("")

    const nodeManager = useContext(NodeManagerContext);

    const [currentNode, setCurrentNode] = useState("")

    const [peer, setPeer] = useState("")

    const [invoiceToPay, setInvoiceToPay] = useState("")

    const [keysend, setKeysend] = useState("")

    // Send state
    const [txid, setTxid] = useState("...")
    const [amount, setAmount] = useState("")
    const [destinationAddress, setDestinationAddress] = useState("")

    const [proxyAddress, setProxyAddress] = useState("ws://127.0.0.1:3001")
    const [connectPeer, setConnectPeer] = useState("")
    const [disconnectPeer, setDisconnectPeer] = useState("")

    function handleAmountChange(e: React.ChangeEvent<HTMLInputElement>) {
        setAmount(e.target.value);
    }

    function handleDestinationAddressChange(e: React.ChangeEvent<HTMLInputElement>) {
        setDestinationAddress(e.target.value);
    }

    function handlePeerChange(e: React.ChangeEvent<HTMLInputElement>) {
        setPeer(e.target.value);
    }

    function handleInvoiceToPayChange(e: React.ChangeEvent<HTMLInputElement>) {
        setInvoiceToPay(e.target.value);
    }

    function handleKeysendChange(e: React.ChangeEvent<HTMLInputElement>) {
        setKeysend(e.target.value);
    }

    function handleConnectPeerChange(e: React.ChangeEvent<HTMLInputElement>) {
        setConnectPeer(e.target.value);
    }

    function handleDisconnectPeerChange(e: React.ChangeEvent<HTMLInputElement>) {
        setDisconnectPeer(e.target.value);
    }

    function handleProxyAddressChange(e: React.ChangeEvent<HTMLInputElement>) {
        setProxyAddress(e.target.value);
    }

    function handleTxChange(e: React.ChangeEvent<HTMLInputElement>) {
        setTx(e.target.value);
    }

    function handleCurrentNodeChange(e: React.ChangeEvent<HTMLInputElement>) {
        setCurrentNode(e.target.value);
    }

    async function sync() {
        if (nodeManager) {
            try {
                await nodeManager.sync()
                await updateBalance()
                const fee = nodeManager.estimate_fee_normal()
                setFeeEstimate(fee.toLocaleString())
            } catch (e) {
                console.error(e);
            }
        }
    }

    async function updateBalance() {
        if (nodeManager) {
            try {
                let balance = await nodeManager.get_balance();
                let str = `confirmed: ${balance.confirmed?.toLocaleString()} sats, unconfirmed: ${balance.unconfirmed?.toLocaleString()} sats, ln: ${balance.lightning.toLocaleString()} sats`
                setBalance(str)
            } catch (e) {
                console.error(e);
            }
        }
    }

    async function get_invoice() {
        if (nodeManager) {
            try {
                let invoice = await nodeManager.create_invoice(BigInt(1000), "hello");
		if (invoice.bolt11) {
                    setInvoice(invoice.bolt11)
		}
            } catch (e) {
                console.error(e);
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

    async function openChannel(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.open_channel(currentNode, peer, BigInt(25000));
        } catch (e) {
            console.error(e);
        }
    }

    async function payInvoice(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.pay_invoice(currentNode, invoiceToPay);
        } catch (e) {
            console.error(e);
        }
    }

    async function sendKeysend(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.keysend(currentNode, keysend, BigInt(5000));
        } catch (e) {
            console.error(e);
        }
    }

    async function connect_peer(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.connect_to_peer(currentNode, connectPeer)
        } catch (e) {
            console.error(e);
        }
    }

    async function disconnect_peer(e: React.SyntheticEvent) {
        e.preventDefault()
        try {
            await nodeManager?.disconnect_peer(currentNode, disconnectPeer)
        } catch (e) {
            console.error(e);
        }
    }

    async function new_node() {
        if (nodeManager) {
            try {
                let new_node_identity = await nodeManager.new_node()
                if (new_node_identity) {
                    setCurrentNode(new_node_identity.pubkey)
                }
            } catch (e) {
                console.error(e)
            }
        }
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
                {nodeManager &&
                    <>
                        <p>
                            <button onClick={() => setMnemonic(nodeManager.show_seed())}>Reveal Seed!</button>
                        </p>
                        <p>
                            {`Wallet Balance: ${balance}`}
                        </p>
                        <p>
                            <button onClick={async () => updateBalance()}>Update Balance</button>
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
                            <pre>
                                Fee Estimate: <code>{feeEstimate}</code> sats/KW
                            </pre>
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

                        <input type="text" placeholder='...' onChange={handleCurrentNodeChange} value={currentNode}></input>
                        <p>
                            <button onClick={async () => new_node()}>New Node!</button>
                        </p>
			    <>
                            <pre>
                                <code>{invoice}</code>
                            </pre>

                            <button onClick={async () => get_invoice()}>Get Invoice</button>

                            <form onSubmit={connect_peer} className="flex flex-col items-start gap-4 my-4">
                                <h2>Connect Peer:</h2>
                                <p>You may want to use "wss://websocket-tcp-proxy-fywbx.ondigitalocean.app" as the example websocket proxy</p>
                                <input type="text" placeholder='Websocket Proxy Address' onChange={handleProxyAddressChange} value={proxyAddress}></input>
                                <input type="text" placeholder='Peer Connection String' onChange={handleConnectPeerChange}></input>
                                <input type="submit" value="Connect" />
                            </form>
                            <form onSubmit={disconnect_peer} className="flex flex-col items-start gap-4 my-4">
                                <h2>Disconnect Peer:</h2>
                                <input type="text" placeholder='Peer' onChange={handleDisconnectPeerChange}></input>
                                <input type="submit" value="Disconnect" />
                            </form>
			    </>
                        <form onSubmit={openChannel} className="flex flex-col items-start gap-4 my-4">
                            <h2>Open Channel:</h2>
                            <input type="text" placeholder='02..' onChange={handlePeerChange}></input>
                            <input type="submit" value="Open Channel" />
                        </form>
                        <form onSubmit={payInvoice} className="flex flex-col items-start gap-4 my-4">
                            <h2>Pay Invoice:</h2>
                            <input type="text" placeholder='lnbc...' onChange={handleInvoiceToPayChange}></input>
                            <input type="submit" value="Pay Invoice" />
                        </form>
                        <form onSubmit={sendKeysend} className="flex flex-col items-start gap-4 my-4">
                            <h2>Keysend:</h2>
                            <input type="text" placeholder='02...' onChange={handleKeysendChange}></input>
                            <input type="submit" value="Send" />
                        </form>
                    </>
                }
            </main>
        </div>
    );
}

export default App;
