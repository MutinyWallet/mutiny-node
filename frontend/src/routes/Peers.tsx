import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

function SinglePeer() {

    return (
        <li className="text-off-white border-b border-off-white py-2 mb-2 flex flex-col">
            <h3 className="text-lg">
                ACINQ
            </h3>
            <h3>Bytes Sent: 0.01MB</h3>
            <h3>Bytes Received: 0.63MB</h3>
        </li>
    )
}

function Peers() {
    return (
        <div className="h-full">
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Peers" theme="white" />
                <Close />
            </header>
            <ScreenMain padSides={false}>
                <button className="mx-8">Add Peer</button>
                <ul className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    <SinglePeer />
                    <SinglePeer />
                    <SinglePeer />
                    <SinglePeer />
                    <SinglePeer />
                    <SinglePeer />
                    <SinglePeer />
                </ul>
            </ScreenMain>
        </div>
    )
}

export default Peers