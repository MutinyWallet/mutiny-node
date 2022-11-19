import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";


export default function OpenChannel() {
	return (

		<div className="flex flex-col h-full w-full">
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Open Channel" theme="blue"></PageTitle>
				<Close />
			</header>

			<ScreenMain>
				<div />
				<p className="text-2xl font-light">Let's do this!</p>
				<div className="flex flex-col gap-4">
					<input className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Target node' />
					<input className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='How big?' />
				</div>
				<div className="flex justify-start">
					<button>Create</button>
				</div>
			</ScreenMain>

		</div>
	)


}
