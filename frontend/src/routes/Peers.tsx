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
import { MutinyPeer } from "node-manager";
import useScreenWidth from "@util/screenWidth";

function SinglePeer({ peer }: { peer: MutinyPeer }) {

    const queryClient = useQueryClient()
    const screenWidth = useScreenWidth();
    const { nodeManager } = useContext(NodeManagerContext);

    async function handleDisconnectPeer() {
        const myNodes = await nodeManager?.list_nodes();

        console.log(myNodes);

        if (window.confirm("Are you sure you want to disconnect this peer?")) {
            const myNode = myNodes[0]
            await nodeManager?.disconnect_peer(myNode, peer.pubkey);
            queryClient.invalidateQueries({ queryKey: ['peers'] })
        }
    }

    async function handleDeletePeer() {
        const myNodes = await nodeManager?.list_nodes();

        console.log(myNodes);

        if (window.confirm("Are you sure you want to delete this peer?")) {
            const myNode = myNodes[0]
            await nodeManager?.delete_peer(myNode, peer.pubkey);
            queryClient.invalidateQueries({ queryKey: ['peers'] })
        }
    }

    function handleClickEject() {
        if (peer.is_connected) {
            handleDisconnectPeer()
        } else {
            handleDeletePeer()
        }
    }

    return (
        <li className="text-off-white border-b border-off-white py-2 mb-2 flex flex-col w-full">
            <div className="flex items-center space-between gap-4">
                <div>
                    <Copy copyValue={peer.pubkey} />
                </div>
                <div className="flex-1 font-mono overflow-ellipsis">
                    <h3 className="text-lg">
                        {takeN(peer.pubkey, 0.05, screenWidth)}
                    </h3>
                    {peer.is_connected && <h5 className="text-green">Connected</h5>}
                    {!peer.is_connected && <h5 className="text-red">Disconnected</h5>}
                </div>
                <button onClick={handleClickEject} className="h-[3rem] w-[3rem] p-1 flex items-center justify-center flex-0"><EjectIcon /></button>
            </div>
        </li>
    )
}

function Peers() {
    const { nodeManager } = useContext(NodeManagerContext);

    const navigate = useNavigate();

    function handleNavConnect() {
        navigate("/connectpeer")
    }

    const { data: peers } = useQuery({
        queryKey: ['peers'],
        queryFn: () => {
            console.log("Getting peers...")
            return nodeManager?.list_peers() as Promise<MutinyPeer[]>
        },
        enabled: !!nodeManager,
        refetchInterval: 1000,
    })

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Peers" theme="white" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={!peers || peers.length < 4}>
                <button className="mx-8" onClick={handleNavConnect}>Add Peer</button>
                <ul className="overflow-y-scroll px-8 pb-[12rem] h-full">
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