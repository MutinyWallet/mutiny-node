import Copy from "@components/Copy";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import takeN from "@util/takeN";
import { useContext } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"
import { ReactComponent as EjectIcon } from "../images/icons/eject.svg"

function SinglePeer({ peer }: { peer: string }) {

    const queryClient = useQueryClient()
    const nodeManager = useContext(NodeManagerContext);

    async function handleDisconnectPeer() {
        const myNodes = await nodeManager?.list_nodes();

        console.log(myNodes);

        const myNode = myNodes[0]
        await nodeManager?.disconnect_peer(myNode, peer);
        queryClient.invalidateQueries({ queryKey: ['peers'] })
    }

    return (
        <li className="text-off-white border-b border-off-white py-2 mb-2 flex flex-col w-full">
            <div className="flex items-center space-between gap-4">
                <Copy copyValue={peer} />
                <h3 className="flex-1 text-lg font-mono overflow-ellipsis">
                    {takeN(peer, 20)}
                </h3>
                <button onClick={handleDisconnectPeer} className="h-[3rem] w-[3rem] p-1 flex items-center justify-center flex-0"><EjectIcon /></button>
            </div>
        </li>
    )
}

function Peers() {
    const nodeManager = useContext(NodeManagerContext);

    const navigate = useNavigate();

    function handleNavConnect() {
        navigate("/connectpeer")
    }

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
                <button className="mx-8" onClick={handleNavConnect}>Add Peer</button>
                <ul className="overflow-y-scroll px-8 pb-[12rem]">
                    {peers?.map((peer, i) => (
                        <SinglePeer peer={peer} key={i} />
                    ))}
                </ul>
                <div />
            </ScreenMain>
        </>
    )
}

export default Peers