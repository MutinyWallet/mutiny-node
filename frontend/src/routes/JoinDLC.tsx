import MutinyToaster from "@components/MutinyToaster";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";

export default function JoinDLC() {
	const navigate = useNavigate();

	function handleNavInspect() {
		navigate("/join-dlc/confirm")
	}

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Join a DLC" theme="blue"></PageTitle>
				<Close route="/manager/dlcs" />
			</header>

			<ScreenMain>
				<div />
				<p className="text-2xl font-light">Bet on tomorrow's Bitcoin Price</p>
				<input onChange={() => { }} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Paste a DLC announcement' />
				<div className="flex justify-start">
					<button onClick={handleNavInspect} disabled={false}>Inspect</button>
				</div>
				<MutinyToaster />
			</ScreenMain>
		</>
	)
}
