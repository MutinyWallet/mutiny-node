import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import { useContext, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import ReceiveUnified, { QRMode } from "@components/ReceiveUnified";
import { useSearchParams } from "react-router-dom";
import { MutinyBip21RawMaterials } from "node-manager";
import { objectToSearchParams } from "@util/dumb";

export type ReceiveParams = {
    amount?: string;
    description?: string;
}

function formatBip21RawMaterial(bip21Raw: MutinyBip21RawMaterials): string {
    const params = objectToSearchParams({
        amount: bip21Raw.btc_amount,
        label: bip21Raw.description,
        lightning: bip21Raw.invoice
    })

    return `bitcoin:${bip21Raw.address}?${params}`
}

export default function ReceiveQR() {
    let navigate = useNavigate();
    const [searchParams] = useSearchParams();

    const { nodeManager } = useContext(NodeManagerContext);
    const [mode, setMode] = useState<QRMode>('bip21');

    const amount = searchParams.get("amount")
    const description = searchParams.get("description")

    function handleCancel() {
        navigate("/")
    }

    const { isLoading, data: bip21RawMaterial } = useQuery({
        // By making amount and description keys, they should automatically redo the query when they change
        queryKey: ['bip21', amount, description],
        queryFn: () => {
            if (!amount) {
                return nodeManager?.create_bip21(undefined, description || undefined);
            } else {
                let amountInt = BigInt(amount);
                if (typeof amountInt !== "bigint") {
                    throw new Error("Invalid amount")
                }
                console.log("Getting new invoice...")
                return nodeManager?.create_bip21(amountInt, description || undefined);
            }
        },
        enabled: !!nodeManager,
        // Don't want a new address each time they focus the window
        refetchOnWindowFocus: false,
        // Important! Without this, it will use a stale version of bip21RawMaterial which has already been paid
        cacheTime: 0
    })

    function handleSetMode(mode: QRMode) {
        setMode(mode)
    }

    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            <ScreenMain>
                <div />

                <div className="flex gap-2">
                    <button onClick={() => handleSetMode("bip21")} disabled={mode === "bip21"} className={mode !== "bip21" ? "secondary" : "toggle"}>Unified</button>
                    <button onClick={() => handleSetMode("lightning")} disabled={mode === "lightning"} className={mode !== "lightning" ? "secondary" : "toggle"}>Lightning</button>
                    <button onClick={() => handleSetMode("onchain")} disabled={mode === "onchain"} className={mode !== "onchain" ? "secondary" : "toggle"}>On-chain</button>
                </div>

                {isLoading &&
                    <p className="text-2xl font-light">Loading...</p>
                }
                {bip21RawMaterial && !isLoading &&
                    <div className="flex flex-col items-start gap-4">
                        <ReceiveUnified bip21String={formatBip21RawMaterial(bip21RawMaterial)} mode={mode} />
                    </div>
                }
                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>Cancel</button>
                </div>
            </ScreenMain>
        </>
    );
}

