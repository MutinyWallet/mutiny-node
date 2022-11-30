import MutinyToaster from "@components/MutinyToaster";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";
import Bear from "@images/48/bear.gif"
import Bull from "@images/48/bull.gif"

export default function NewDLC() {
	const navigate = useNavigate();

	const [bullish, setBullish] = useState(false);

	function handleNavCreate() {
		navigate("/new-dlc/confirm")
	}

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Create a DLC" theme="green"></PageTitle>
				<Close route="/manager/dlcs" />
			</header>

			<ScreenMain>
				<div />
				<p className="text-2xl font-light">Bet on tomorrow's Bitcoin Price</p>
				<div className="flex flex-col gap-4">
					<div className="flex gap-2">
						<button onClick={() => setBullish(false)} className={bullish ? "secondary" : ""} >
							<img src={Bear} alt="bearish" />
							Short
						</button>
						<button onClick={() => setBullish(true)} className={!bullish ? "secondary" : ""} >
							<img src={Bull} alt="bullish" />
							Long
						</button>
					</div>
					<div className="flex flex-col">
						<p className="text-lg font-light">{bullish ? "Pay out the stable dollar value of BTC, keep (or lose) the difference." : "Get a stable dollar value for your BTC when the DLC closes."}</p>
						<a href="#/">Learn More</a>
					</div>
				</div>
				<div className="flex flex-col gap-4">
					<p className="text-2xl font-light">How {bullish ? "bullish" : "bearish"} are you?</p>
					<input onChange={() => { }} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='sats' />
				</div>
				<div className="flex justify-start">
					<button onClick={handleNavCreate} disabled={false}>Create</button>
				</div>
				<MutinyToaster />
			</ScreenMain>
		</>
	)
}
