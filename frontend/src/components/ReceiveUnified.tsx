import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useContext } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import takeN from "@util/takeN";
import { useNavigate } from "react-router-dom";
import bip21 from "bip21";
import { MutinyBip21 } from "@routes/Send";

export default function ReceiveUnified({ bip21String }: { bip21String: string }) {
    const nodeManager = useContext(NodeManagerContext);
    let navigate = useNavigate();

    const { address, options } = bip21.decode(bip21String) as MutinyBip21;

    const { isLoading: isCheckingAddress } = useQuery({
        queryKey: ['checktransaction'],
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
        refetchInterval: 1000
    })

    useQuery({
        queryKey: ['checkinvoice'],
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
        refetchInterval: 1000
    })

    return (
        <>
            {bip21 &&
                <>
                    <div className="bg-[#ffffff] p-4">
                        <QRCode level="M" value={bip21String.toUpperCase()} />
                    </div>
                    <div className="flex items-center gap-2 w-full">
                        {/* <p className="text-lg font-mono font-light break-all"> */}
                        <pre className="flex-1">
                            <code className="break-all whitespace-nowrap overflow-hidden overflow-ellipsis">
                                {takeN(bip21String, 28)}
                            </code>
                        </pre>
                        <div className="flex-0">
                            <Copy copyValue={bip21String} />
                        </div>
                    </div>
                    {isCheckingAddress &&
                        <p className="text-2xl font-light transition-all">Checking...</p>
                    }
                </>
            }
        </>
    );
}
