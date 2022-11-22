import { NodeManagerContext } from "@components/GlobalStateProvider";
import { getFirstNode } from "@util/dumb";
import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";

const WS_PROXY_ADDRESS = "wss://websocket-tcp-proxy-fywbx.ondigitalocean.app"

export default function ConnectPeer() {
	const nodeManager = useContext(NodeManagerContext);
	const navigate = useNavigate();

	const [peerConnectString, setPeerConnectString] = useState("")

	function handlePeerChange(e: React.ChangeEvent<HTMLInputElement>) {
		setPeerConnectString(e.target.value)
	}
	async function handleConnectPeer() {
		try {
			const myNode = await getFirstNode(nodeManager!);

			await nodeManager?.connect_to_peer(myNode, WS_PROXY_ADDRESS, peerConnectString)

			navigate("/manager/peers")
		} catch (e) {
			console.error(e)
		}
	}
	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Connect to peer" theme="red"></PageTitle>
				<Close />
			</header>

			<ScreenMain>
				<div />
				<p className="text-2xl font-light">Let's do this!</p>
				<div className="flex flex-col gap-4">
					<input onChange={handlePeerChange} className={`w-full ${inputStyle({ accent: "red" })}`} type="text" placeholder='Target peer' />
				</div>
				<div className="flex justify-start">
					<button onClick={handleConnectPeer} disabled={!peerConnectString}>Connect</button>
				</div>
			</ScreenMain>
		</>
	)
}
