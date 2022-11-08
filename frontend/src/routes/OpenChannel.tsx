import { inputStyle } from "../styles";


export default function OpenChannel() {
	return (
		<div className="flex flex-col gap-2">
			<input className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Target node' />
			<input className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='How big?' />
		</div>
	)
}
