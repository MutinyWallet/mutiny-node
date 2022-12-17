import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useContext, useEffect, useState } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import takeN from "@util/takeN";
import { useNavigate } from "react-router-dom";
import bip21 from "bip21";
import { MutinyBip21 } from "@routes/Send";

export type QRMode = "lightning" | "onchain" | "bip21";

export default function ReceiveUnified({ bip21String, mode }: { bip21String: string, mode: QRMode }) {
    const { nodeManager } = useContext(NodeManagerContext);
    let navigate = useNavigate();

    const { address, options } = bip21.decode(bip21String) as MutinyBip21;

    const [activeString, setActiveString] = useState("");

    useEffect(() => {
        if (mode === "lightning") {
            setActiveString(options.lightning ?? "")
        } else if (mode === "onchain") {
            setActiveString(address)
        } else if (mode === "bip21") {
            setActiveString(bip21String)
        }
    }, [mode, bip21String, address, options.lightning])

    useQuery({
        queryKey: ['checktransaction', address],
        queryFn: async () => {
            console.log("Checking address:", address);
            const tx = await nodeManager?.check_address(address);
            if (!tx) {
                return false
            } else {
                console.log(tx)
                navigate(`/receive/final?address=${address}`)
                return tx
            }
        },
        enabled: !!address,
        refetchOnMount: "always",
        refetchInterval: 1000
    })

    useQuery({
        queryKey: ['checkinvoice', options.lightning],
        queryFn: async () => {
            if (options.lightning) {
                let invoice = await nodeManager?.decode_invoice(options.lightning);
                console.log("Checking invoice:", invoice?.payment_hash);
                let checked = await nodeManager?.get_invoice(invoice?.bolt11!);
                if (!checked) {
                    return false
                } else {
                    console.log("is paid", checked.paid)
                    if (checked.paid) {
                        navigate(`/receive/final?payment_hash=${checked.payment_hash}`)
                    }
                    return checked
                }

            }
        },
        enabled: !!options.lightning,
        refetchOnMount: "always",
        refetchInterval: 1000
    })

    return (
        <>
            {bip21 && activeString &&
                <>
                    <div className="bg-[#ffffff] p-4">
                        <QRCode level="M" value={activeString} />
                    </div>
                    <div className="flex items-center gap-2 w-full">
                        <pre className="flex-1">
                            <code className="break-all whitespace-nowrap overflow-hidden overflow-ellipsis">
                                {takeN(activeString, 28)}
                            </code>
                        </pre>
                        <div className="flex-0">
                            <Copy copyValue={activeString} />
                        </div>
                    </div>
                </>
            }
        </>
    );
}
