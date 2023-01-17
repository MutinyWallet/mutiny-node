import Copy from "@components/Copy";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import takeN from "@util/takeN";
import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import { ReactComponent as EjectIcon } from "../images/icons/eject.svg"
import { MutinyPeer } from "node-manager";
import { mainWrapperStyle } from "../styles";
import { toastAnything } from "@util/dumb";
import MutinyToaster from "@components/MutinyToaster";
import ConfirmDialog from "@components/ConfirmDialog";

function SinglePeer({ peer }: { peer: MutinyPeer }) {

    const queryClient = useQueryClient()
    const { nodeManager } = useContext(NodeManagerContext);

    const [dialogOpen, setDialogOpen] = useState(false);
    const [confirmMessage, setConfirmMessage] = useState("");

    async function confirmPeerAction() {
        const myNodes = await nodeManager?.list_nodes();
        const myNode = myNodes[0]

        try {
            if (peer.is_connected) {
                await nodeManager?.disconnect_peer(myNode, peer.pubkey);
                await queryClient.invalidateQueries({ queryKey: ['peers'] })
                toastAnything("Disconnected peer");
            } else {
                await nodeManager?.delete_peer(myNode, peer.pubkey);
                await queryClient.invalidateQueries({ queryKey: ['peers'] })
                toastAnything("Deleted peer");
            }
        } catch (e) {
            toastAnything(e);
            setDialogOpen(false);
        }

        queryClient.invalidateQueries({ queryKey: ['peers'] })
        setDialogOpen(false);
    }

    function handleClickEject() {
        if (peer.is_connected) {
            setConfirmMessage("Are you sure you want to disconnect this peer?");
            setDialogOpen(true);
        } else {
            setConfirmMessage("Are you sure you want to delete this peer?");
            setDialogOpen(true);
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
                        {takeN(peer.pubkey, 15)}
                    </h3>
                    {peer.is_connected && <h5 className="text-green">Connected</h5>}
                    {!peer.is_connected && <h5 className="text-red">Disconnected</h5>}
                </div>
                <button onClick={handleClickEject} className="h-[3rem] w-[3rem] p-1 flex items-center justify-center flex-0"><EjectIcon /></button>
            </div>
            <ConfirmDialog open={dialogOpen} message={confirmMessage} onCancel={() => setDialogOpen(false)} onConfirm={confirmPeerAction} />
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
            const peers = nodeManager?.list_peers() as Promise<MutinyPeer[]>
            return peers
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
            <main className={mainWrapperStyle({ padSides: "no" })}>
                <button className="mx-8" onClick={handleNavConnect}>Add Peer</button>
                <ul className="overflow-y-scroll px-8 pb-[12rem] h-full">
                    {peers?.map((peer, i) => (
                        <SinglePeer peer={peer} key={i} />
                    ))}
                </ul>
                <div />
            </main>
            <MutinyToaster />
        </>
    )
}

export default Peers