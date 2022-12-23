import Copy from "@components/Copy";
import { getExistingSettings, NodeManagerContext, NodeManagerSettingStrings } from "@components/GlobalStateProvider";
import MutinyToaster from "@components/MutinyToaster";
import { useQuery } from "@tanstack/react-query";
import { getFirstNode, getHostname, toastAnything } from "@util/dumb";
import takeN from "@util/takeN";
import React, { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";

export default function ConnectPeer() {
	const { nodeManager } = useContext(NodeManagerContext);
	const navigate = useNavigate();

	const [peerConnectString, setPeerConnectString] = useState("")
	const [nodeManagerSettings] = useState<NodeManagerSettingStrings>(getExistingSettings());

	function handlePeerChange(e: React.ChangeEvent<HTMLInputElement>) {
		setPeerConnectString(e.target.value)
	}

	const handleKeyDown = async (event: React.KeyboardEvent) => {
		if (event.key === 'Enter') {
			await handleConnectPeer()
		}
	};

	async function handleConnectPeer() {
		try {
			const myNode = await getFirstNode(nodeManager!);

			await nodeManager?.connect_to_peer(myNode, peerConnectString)

			navigate("/manager/peers")
		} catch (e) {
			console.error(e)
			toastAnything(e);
		}
	}

	const { data: connectionString } = useQuery({
		queryKey: ['connectionString'],
		queryFn: async () => {
			let firstNode = await getFirstNode(nodeManager!);
			// TODO: can I handle undefined better here? Not sure what should happen in that case.
			let proxy = getHostname(nodeManagerSettings.proxy || "");
			return `mutiny:${firstNode}@${proxy}`
		},
		enabled: !!nodeManager,
	})

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Connect to peer" theme="red"></PageTitle>
				<Close to="/manager/peers" />
			</header>

			<ScreenMain>
				<div />
				{connectionString &&
					<div className="flex flex-col gap-4">
						<p className="text-2xl font-light">Want to connect to a Mutiny user? Here's your connection string</p>
						<div className="flex gap-4 items-center w-full">
							<pre className="flex-1">
								{/* TODO: learn how to make this responsive and actually do overflow right */}
								<code className="break-all whitespace-nowrap">
									{takeN(connectionString, 28)}
								</code>
							</pre>
							<div className="flex-0">
								<Copy copyValue={connectionString} />
							</div>
						</div>
					</div>
				}
				<div className="flex flex-col gap-4">
					<p className="text-2xl font-light">Or you can enter your peer's connection string</p>
					<input onChange={handlePeerChange} onKeyDown={handleKeyDown} className={`w-full ${inputStyle({ accent: "red" })}`} type="text" placeholder='Target peer' />
				</div>
				<div className="flex justify-start">
					<button onClick={handleConnectPeer} disabled={!peerConnectString}>Connect</button>
				</div>
				<MutinyToaster />
			</ScreenMain>
		</>
	)
}
