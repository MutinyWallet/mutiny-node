import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useContext } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import takeNWidth from "@util/takeNWidth";
import { useNavigate } from "react-router-dom";
import { MutinyInvoice } from "node-manager";
import useScreenWidth from "@util/screenWidth";

export default function ReceiveLightning({ invoice }: { invoice: MutinyInvoice | undefined }) {
    const { nodeManager } = useContext(NodeManagerContext);
    const screenWidth = useScreenWidth();
    let navigate = useNavigate();

    useQuery({
        queryKey: ['checkinvoice'],
        queryFn: async () => {
            console.log("Checking invoice:", invoice?.payment_hash);
            // let checked = await nodeManager?.get_invoice_by_hash(invoice?.payment_hash!);
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
        },
        enabled: !!invoice?.payment_hash,
        refetchInterval: 1000
    })

    return (
        <>
            {invoice &&
                <>
                    <div className="bg-[#ffffff] p-4">
                        <QRCode value={invoice.bolt11!} />
                    </div>
                    <div className="flex items-center gap-2 w-full">
                        {/* <p className="text-lg font-mono font-light break-all"> */}
                        <pre className="flex-1">
                            <code className="break-all whitespace-nowrap overflow-hidden overflow-ellipsis">
                                {takeNWidth(invoice.bolt11!, 0.065, screenWidth)}
                            </code>
                        </pre>
                        <div className="flex-0">
                            <Copy copyValue={invoice.bolt11!} />
                        </div>
                    </div>
                </>
            }
        </>
    );
}
