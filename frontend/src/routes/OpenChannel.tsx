import { NodeManagerContext } from "@components/GlobalStateProvider";
import { getFirstNode } from "@util/dumb";
import { useContext, useState } from "react";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";


export default function OpenChannel() {
	const nodeManager = useContext(NodeManagerContext);

	const [peerPubkey, setPeerPubkey] = useState("");
	const [amount, setAmount] = useState("")

	async function handleOpenChannel() {
		try {
			const myNode = await getFirstNode(nodeManager!);

			let amountBig = BigInt(amount)

			if (typeof amountBig !== "bigint") {
				throw new Error("Didn't get a usable amount")
			}

			let mutinyChannel = await nodeManager?.open_channel(myNode, peerPubkey, amountBig)

			console.log("MUTINY CHANNEL")
			console.table(mutinyChannel)

			// navigate("/manager/channels")
		} catch (e) {
			console.error(e)
		}
	}

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Open Channel" theme="blue"></PageTitle>
				<Close />
			</header>

			<ScreenMain>
				<div />
				<p className="text-2xl font-light">Let's do this!</p>
				<div className="flex flex-col gap-4">
					<input onChange={(e) => setPeerPubkey(e.target.value)} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Target node pubkey' />
					<input onChange={(e) => setAmount(e.target.value)} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='How big?' />
				</div>
				<div className="flex justify-start">
					<button onClick={handleOpenChannel}>Create</button>
				</div>
			</ScreenMain>

		</>
	)
}
