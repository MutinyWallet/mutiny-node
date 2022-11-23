import { NodeManagerContext } from "@components/GlobalStateProvider"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { mempoolTxUrl } from "@util/dumb"
import prettyPrintAmount from "@util/prettyPrintAmount"
import { MutinyChannel } from "node-manager"
import { useContext } from "react"
import { useNavigate } from "react-router-dom"
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"
import { ReactComponent as EjectIcon } from "../images/icons/eject.svg"

function SingleChannel({ channel }: { channel: MutinyChannel }) {
    console.table(channel);

    const queryClient = useQueryClient()
    const nodeManager = useContext(NodeManagerContext);

    // TODO: this should warn before closing
    async function handleCloseChannel() {
        await nodeManager?.close_channel(channel.outpoint!);
        queryClient.invalidateQueries({ queryKey: ['channels'] })
    }

    let percent = Number(channel.balance / channel.size) * 100
    return (
        <li className="text-off-white border-b border-blue py-2 mb-2 flex flex-col w-full">
            {!channel.confirmed && <h3 className="font-light text-2xl opacity-70">UNCONFIRMED</h3>}
            <h3 className="text-lg">
                {channel.peer}
            </h3>
            <div className="flex items-center gap-4">
                <div className="flex-1 flex flex-col gap-2">
                    <h3 className="text-lg">{prettyPrintAmount(channel.balance)} sats remaining</h3>
                    <div className="shadow-bar-bg h-6 bg-less-faint rounded">
                        <div className={"shadow-button bg-blue-button h-6 rounded"} style={{ width: `${percent}%` }} />
                    </div>
                </div>
                <button onClick={handleCloseChannel} className="h-[3rem] w-[3rem] p-1 flex items-center justify-center flex-0"><EjectIcon /></button>
            </div>
            <a className="text-sm font-light opacity-50 mt-2" href={mempoolTxUrl(channel.outpoint?.split(":")[0], nodeManager?.get_network())} target="_blank" rel="noreferrer">
                {channel.outpoint}
            </a>
        </li>
    )
}

function Channels() {

    const navigate = useNavigate();

    function handleNavOpen() {
        navigate("/openchannel")
    }

    const nodeManager = useContext(NodeManagerContext);

    const { data: channels } = useQuery({
        queryKey: ['channels'],
        queryFn: () => {
            console.log("Getting channels...")
            const txs = nodeManager?.list_channels() as Promise<MutinyChannel[]>;
            return txs
        },
        enabled: !!nodeManager,
        refetchInterval: 1000
    })

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Channels" theme="blue" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={!channels || channels.length < 4}>
                <button className="mx-8" onClick={handleNavOpen}>Add Channel</button>
                <ul className="overflow-y-scroll px-8 pb-[12rem] w-full h-full">
                    {channels?.map((channel, i) => (
                        <SingleChannel channel={channel} key={i} />
                    ))}
                </ul>
            </ScreenMain>
        </>
    )
}

export default Channels