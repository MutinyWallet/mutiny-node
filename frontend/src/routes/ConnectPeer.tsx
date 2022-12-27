import ActionButton from "@components/ActionButton";
import Copy from "@components/Copy";
import { getExistingSettings, NodeManagerContext, NodeManagerSettingStrings } from "@components/GlobalStateProvider";
import MutinyToaster from "@components/MutinyToaster";
import { useQuery } from "@tanstack/react-query";
import { getFirstNode, getHostname, toastAnything } from "@util/dumb";
import takeN from "@util/takeN";
import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import { inputStyle, mainWrapperStyle } from "../styles";

export default function ConnectPeer() {
	const { nodeManager } = useContext(NodeManagerContext);
	const navigate = useNavigate();

	const [peerConnectString, setPeerConnectString] = useState("")
	const [nodeManagerSettings] = useState<NodeManagerSettingStrings>(getExistingSettings());

	function handlePeerChange(e: React.ChangeEvent<HTMLInputElement>) {
		setPeerConnectString(e.target.value)
	}

	async function handleSubmit(e: React.SyntheticEvent) {
		e.preventDefault()
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

			<main>
				<form onSubmit={handleSubmit} className={mainWrapperStyle()}>
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
						<input onChange={handlePeerChange} className={`w-full ${inputStyle({ accent: "red" })}`} type="text" placeholder='Target peer' />
					</div>
					<ActionButton>Connect</ActionButton>
				</form>
			</main>
			<MutinyToaster />
		</>
	)
}
