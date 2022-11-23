import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useContext } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import takeN from "@util/takeN";
import { useNavigate } from "react-router-dom";

export default function ReceiveLightning() {
    const nodeManager = useContext(NodeManagerContext);
    let navigate = useNavigate();

    const { data: invoice } = useQuery({
        queryKey: ['lightninginvoice'],
        queryFn: () => {
            console.log("Getting new invoice...")
            return nodeManager?.create_invoice(BigInt(0), "testing 123");
        },
        enabled: !!nodeManager,
        // Don't want a new address each time they focus the window
        refetchOnWindowFocus: false
    })

    const { data: checkedInvoice } = useQuery({
        queryKey: ['checkinvoice'],
        queryFn: async () => {
            console.log("Checking invoice:", invoice?.payment_hash);
            let checked = await nodeManager?.get_invoice_by_hash(invoice?.payment_hash!);

            if (!checked) {
                return false
            } else {
                console.log("is paid", checked.paid)
                if (checked.paid) {
                    navigate(`receive/final?payment_hash=${checked.payment_hash}`)
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
                                {takeN(invoice.bolt11!, 28)}
                            </code>
                        </pre>
                        <div className="flex-0">
                            <Copy copyValue={invoice.bolt11!} />
                        </div>
                    </div>
                    <p className="text-2xl font-light transition-all">Checking...</p>
                </>
            }
        </>
    );
}
