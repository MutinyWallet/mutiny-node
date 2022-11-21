
// This is so dumb why react why
type Props = {
	children?: React.ReactNode
	padSides?: boolean
	wontScroll?: boolean
}

const ScreenMain: React.FC<Props> = ({ children, padSides = true, wontScroll = false }) => {
	return (<main className={`flex flex-col justify-between overflow-y-scroll ${padSides ? "p-8" : "py-8"} mb-4 gap-4 ${wontScroll && "h-full"}`}>
		{children}
	</main>
	)
}

export default ScreenMain
