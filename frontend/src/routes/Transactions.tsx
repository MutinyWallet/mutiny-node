import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import prettyPrintAmount from "@util/prettyPrintAmount";
import prettyPrintTime from "@util/prettyPrintTime";
import { MutinyInvoice } from "@mutinywallet/node-manager";
import { useContext } from "react";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import { mainWrapperStyle } from "../styles";

function SingleTransaction({ invoice }: { invoice: MutinyInvoice }) {
    return (
        <li className="text-off-white border-b border-green py-2 mb-2">
            {invoice.description &&
                <h3 className="text-lg font-light">
                    {invoice.description}
                </h3>
            }
            {!invoice.is_send &&
                <h3 className="text-lg font-light"><span className="text-green">Received</span> {prettyPrintAmount(invoice.amount_sats)} sats</h3>
            }
            {invoice.is_send &&
                <h3 className="text-lg font-light"><span className="text-red">Sent</span> {prettyPrintAmount(invoice.amount_sats)} sats</h3>
            }
            <h3 className="text-lg font-light opacity-70">
                {invoice.paid ? "Paid" : "Not paid"}
            </h3>
            <h4 className="text-sm font-light opacity-50">{prettyPrintTime(Number(invoice.expire))}</h4>
        </li>
    )
}

function sortByExpiry(a: MutinyInvoice, b: MutinyInvoice): number {
    return Number(b.expire - a.expire)
}

function Transactions() {
    const { nodeManager } = useContext(NodeManagerContext);

    const { data: invoices } = useQuery({
        queryKey: ['ln_txs'],
        queryFn: () => {
            console.log("Getting lightning transactions...")
            return nodeManager?.list_invoices() as Promise<MutinyInvoice[]>;
        },
        enabled: !!nodeManager,
        refetchInterval: 1000
    })
    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Transactions" theme="green" />
                <Close />
            </header>
            <main className={mainWrapperStyle({ padSides: "no" })}>
                <ul className="overflow-y-scroll px-8 pb-[12rem] h-full">
                    {invoices?.sort(sortByExpiry).map((invoice, i) => (
                        <SingleTransaction invoice={invoice} key={i} />
                    ))}
                </ul>
            </main>
        </>
    )
}

export default Transactions
