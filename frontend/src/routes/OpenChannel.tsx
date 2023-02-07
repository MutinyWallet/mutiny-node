import ActionButton from "@components/ActionButton";
import AmountInput from "@components/AmountInput";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import MutinyToaster from "@components/MutinyToaster";
import { useQuery } from "@tanstack/react-query";
import { getFirstNode, toastAnything } from "@util/dumb";
import { useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import { mainWrapperStyle, selectStyle } from "../styles";
import { MutinyPeer } from "@mutinywallet/node-manager";

export default function OpenChannel() {
	const { nodeManager } = useContext(NodeManagerContext);
	let navigate = useNavigate();

	const { data: peers } = useQuery({
		queryKey: ['peers'],
		queryFn: () => {
			console.log("Getting peers...")
			const peers = nodeManager?.list_peers() as Promise<MutinyPeer[]>
			return peers
		},
		enabled: !!nodeManager,
		refetchInterval: 1000,
	})

	// If we have peers set that as the default peer
	useEffect(() => {
		if (peers && peers.length) {
			setPeerPubkey(peers[0].pubkey)
		}
	}, [peers]);

	const [peerPubkey, setPeerPubkey] = useState("");
	const [channelAmount, setAmount] = useState("")

	async function handleSubmit(e: React.SyntheticEvent) {
		e.preventDefault()
		const amount = channelAmount.replace(/_/g, "")
		if (amount.match(/\D/)) {
			setAmount('')
			toastAnything("That doesn't look right")
			return
		}
		try {
			const myNode = await getFirstNode(nodeManager!);

			let amountBig = BigInt(amount)

			if (typeof amountBig !== "bigint") {
				throw new Error("Didn't get a usable amount")
			}

			let mutinyChannel = await nodeManager?.open_channel(myNode, peerPubkey, amountBig)

			console.log("MUTINY CHANNEL")
			console.table(mutinyChannel)

			navigate("/manager/channels")
		} catch (e) {
			console.error(e)
			toastAnything(e)
		}
	}

	function handleSelectChange(e: React.ChangeEvent<HTMLSelectElement>) {
		setPeerPubkey(e.target.value)
	}

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Open Channel" theme="blue"></PageTitle>
				<Close to="/manager/channels" />
			</header>

			<main>
				{(peers && peers.length > 0) &&
					<form onSubmit={handleSubmit} className={mainWrapperStyle()}>
						<div />
						<>
							<p className="text-2xl font-light">Let's do this!</p>
							<div className="flex flex-col gap-4">
								<div className="flex flex-col gap-2">
									<label className="text-xl font-light">Pick the peer</label>
									<select onChange={handleSelectChange} className={selectStyle({ accent: "blue", overflow: "yes" })} value={peerPubkey} placeholder="Network">
										{peers.map(p => <option key={p.pubkey} value={p.pubkey}>{p.pubkey}</option>)}
									</select>
								</div>
								<AmountInput amountSats={channelAmount} setAmount={setAmount} accent="blue" placeholder="How big?" />
							</div>
							<ActionButton>Create</ActionButton>
						</>
					</form>
				}
				{(!peers || peers.length === 0) &&
					<div className={mainWrapperStyle()}>
						<div />
						<p className="text-2xl font-light">You need to connect to a peer first.</p>
						<ActionButton onClick={() => navigate("/connectpeer")}>Connect Peer</ActionButton>
					</div>
				}
			</main>
			<MutinyToaster />

		</>
	)
}
