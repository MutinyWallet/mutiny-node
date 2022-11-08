
// This is so dumb why react why
type Props = {
	children?: React.ReactNode
}

const ScreenMain: React.FC<Props> = ({ children }) => {
	return (<main className='flex flex-grow flex-col h-full justify-between p-8 mb-4 gap-4'>
		{children}
	</main>
	)
}

export default ScreenMain
