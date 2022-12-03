import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import { useContext } from "react";
import { useQuery } from "@tanstack/react-query";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import ReceiveUnified from "@components/ReceiveUnified";
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

    const nodeManager = useContext(NodeManagerContext);

    const amount = searchParams.get("amount")
    const description = searchParams.get("description")

    function handleCancel() {
        navigate("/")
    }

    const { data: bip21RawMaterial } = useQuery({
        queryKey: ['lightninginvoice'],
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
        refetchOnWindowFocus: false
    })


    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            <ScreenMain>
                <div />
                {bip21RawMaterial &&
                    <div className="flex flex-col items-start gap-4">
                        <ReceiveUnified bip21String={formatBip21RawMaterial(bip21RawMaterial)} />
                    </div>
                }

                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>Cancel</button>
                </div>
            </ScreenMain>
        </>
    );
}

