import { NodeManagerContext } from "@components/GlobalStateProvider";
import MutinyToaster from "@components/MutinyToaster";
import { useContext } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import prettyPrintAmount from "@util/prettyPrintAmount";
import DLItem from "@components/DLItem";
import prettyPrintTime from "@util/prettyPrintTime";

export default function ConfirmJoinDLC() {
	const nodeManager = useContext(NodeManagerContext);
	const navigate = useNavigate();

	function handleNavFinal() {
		navigate("/join-dlc/final")
	}

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Create a DLC" theme="blue"></PageTitle>
				<Close route="/manager/dlcs" />
			</header>
			<ScreenMain>
				<div />
				<p className="text-2xl font-light">How does this look to you?</p>
				<dl>
					<DLItem title="How Much">{prettyPrintAmount(10000)} sats</DLItem>
					<DLItem title="Terms">Long Bitcoin {"<->"} USD</DLItem>
					<DLItem title="Closes">{prettyPrintTime(12345)}</DLItem>
					<DLItem title="Oracle"><a href="https://oracle.suredbits.com/">suredbits-oracle-bot</a></DLItem>
				</dl>
				<div className='flex justify-start'>
					<button onClick={handleNavFinal}>Confirm</button>
				</div>
				<MutinyToaster />
			</ScreenMain>
		</>
	)
}
