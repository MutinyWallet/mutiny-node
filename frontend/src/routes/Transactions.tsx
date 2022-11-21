import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

function SingleTransaction() {
    return (
        <li className="text-off-white border-b border-green py-2 mb-2">
            <h3 className="text-lg">
                Bitcoin Beefsteak
            </h3>
            <h3 className="text-lg">1,440,123 sats</h3>
            <h4 className="text-sm font-light opacity-50">July 4, 2022</h4>
        </li>
    )
}

function Transactions() {
    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Transactions" theme="green" />
                <Close />
            </header>
            <ScreenMain padSides={false}>
                <ul className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                    <SingleTransaction />
                </ul>
            </ScreenMain>
        </>
    )
}

export default Transactions