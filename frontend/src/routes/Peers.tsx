import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import { useContext } from "react";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

function SinglePeer({ peer }: { peer: string }) {
    return (
        <li className="text-off-white border-b border-off-white py-2 mb-2 flex flex-col">
            <h3 className="text-lg">
                {peer}
            </h3>
        </li>
    )
}

function Peers() {
    const nodeManager = useContext(NodeManagerContext);

    const { data: peers } = useQuery({
        queryKey: ['peers'],
        queryFn: () => {
            console.log("Getting peers...")
            const txs = nodeManager?.list_peers() as Promise<string[]>;
            return txs
        },
        enabled: !!nodeManager,
    })

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Peers" theme="white" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={!peers || peers.length < 4}>
                <button className="mx-8">Add Peer</button>

                <ul className="overflow-y-scroll px-8 pb-[12rem]">
                    {peers?.map((peer, i) => (
                        <SinglePeer peer={peer} key={i} />
                    ))}
                </ul>
            </ScreenMain>
        </>
    )
}

export default Peers