import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import prettyPrintTime from "@util/prettyPrintTime";
import takeN from "@util/takeN";
import { useContext } from "react";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

type OnChainTx = {
    txid: string
    received: number
    sent: number
    fee: number
    confirmation_time: {
        height: number
        timestamp: number
    }
}

const SingleTransaction = ({ tx }: { tx: OnChainTx }) => {
    return (
        <li className="text-off-white border-b border-red py-2 mb-2">
            <a href={`https://mempool.space/testnet/tx/${tx.txid}`} target="_blank">
                <h3 className="text-lg font-mono">
                    {takeN(tx.txid, 25)}
                </h3>
            </a>
            {tx.sent !== 0 &&
                <h3 className="text-lg font-light"><span className="text-red">Sent</span> {tx.sent} sats</h3>
            }
            {tx.received !== 0 &&
                <h3 className="text-lg font-light"><span className="text-green">Received</span> {tx.received} sats</h3>
            }
            <h3 className="text-lg font-light"><span className="opacity-70">Fee</span> {tx.fee} sats</h3>
            <h4 className="text-sm font-light opacity-50">{prettyPrintTime(tx.confirmation_time.timestamp)}</h4>

        </li>
    )
}

function OnChain() {
    const nodeManager = useContext(NodeManagerContext);

    const { data: transactions } = useQuery({
        queryKey: ['transactions'],
        queryFn: () => {
            console.log("getting transactions...")
            const txs = nodeManager?.list_onchain() as Promise<OnChainTx[]>;
            return txs
        },
        enabled: !!nodeManager,
    })

    console.log(transactions);
    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="On-chain txs" theme="red" />
                <Close />
            </header>
            <ScreenMain padSides={false}>
                <ul className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    {transactions?.sort((a, b) => b.confirmation_time.timestamp - a.confirmation_time.timestamp).map(tx => (
                        <li>
                            <SingleTransaction tx={tx} />
                        </li>
                    ))}
                </ul>
            </ScreenMain>
        </>
    )
}

export default OnChain