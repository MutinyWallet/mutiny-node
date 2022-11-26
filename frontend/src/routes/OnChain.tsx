import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import { mempoolTxUrl } from "@util/dumb";
import prettyPrintTime from "@util/prettyPrintTime";
import takeN from "@util/takeN";
import { useContext } from "react";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"
import prettyPrintAmount from "@util/prettyPrintAmount";

export type OnChainTx = {
    txid: string
    received: number
    sent: number
    fee?: number
    confirmation_time?: {
        height: number
        timestamp: number
    }
}

const SingleTransaction = ({ tx, network }: { tx: OnChainTx, network?: string }) => {
    return (
        <li className="text-off-white border-b border-red py-2 mb-2">
            <a href={mempoolTxUrl(tx.txid, network)} target="_blank" rel="noreferrer">
                <h3 className="text-lg font-mono">
                    {takeN(tx.txid, 25)}
                </h3>
            </a>
            {tx.sent !== 0 &&
                <h3 className="text-lg font-light"><span className="text-red">Sent</span> {prettyPrintAmount(tx.sent)} sats</h3>
            }
            {tx.received !== 0 &&
                <h3 className="text-lg font-light"><span className="text-green">Received</span> {prettyPrintAmount(tx.received)} sats</h3>
            }
            {tx.fee &&
                <h3 className="text-lg font-light"><span className="opacity-70">Fee</span> {prettyPrintAmount(tx.fee)} sats</h3>
            }
            {tx.confirmation_time ?
                <h4 className="text-sm font-light opacity-50">{prettyPrintTime(tx.confirmation_time.timestamp)}</h4> :
                <h4 className="text-sm font-light opacity-50">Unconfirmed</h4>
            }
        </li>
    )
}

// Sort by timestamp, but if there's no timestamp put it first
function sortTx(a: OnChainTx, b: OnChainTx) {
    if (b.confirmation_time && a.confirmation_time) {
        return b.confirmation_time.timestamp - a.confirmation_time.timestamp
    } else if (a.confirmation_time) {
        return 1
    } else if (b.confirmation_time) {
        return -1
    } else {
        return a.txid.localeCompare(b.txid)
    }
}

function OnChain() {
    const nodeManager = useContext(NodeManagerContext);

    const { data: transactions } = useQuery({
        queryKey: ['transactions'],
        queryFn: () => {
            console.log("Getting transactions...")
            const txs = nodeManager?.list_onchain() as Promise<OnChainTx[]>;
            return txs
        },
        enabled: !!nodeManager,
        refetchInterval: 1000
    })

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="On-chain txs" theme="red" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={!transactions || transactions.length < 4}>
                <ul className="overflow-y-scroll h-full px-8 pb-[12rem]">
                    {transactions?.sort(sortTx).map(tx => (
                        <SingleTransaction key={tx.txid} tx={tx} network={nodeManager?.get_network()} />
                    ))}
                </ul>
            </ScreenMain>
        </>
    )
}

export default OnChain