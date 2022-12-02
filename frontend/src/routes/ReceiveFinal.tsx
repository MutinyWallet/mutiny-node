import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import { useContext } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import takeN from "@util/takeN";
import prettyPrintTime from "@util/prettyPrintTime";
import { useSearchParams } from "react-router-dom";
import { MutinyInvoice } from "node-manager";
import prettyPrintAmount from "@util/prettyPrintAmount";
import { mempoolTxUrl } from "@util/dumb";
import ActionButton from "@components/ActionButton";

export default function ReceiveFinal() {
    let navigate = useNavigate();

    const nodeManager = useContext(NodeManagerContext);

    const [searchParams] = useSearchParams();

    const address = searchParams.get("address")
    const paymentHash = searchParams.get("payment_hash")

    const { data: onchain } = useQuery({
        queryKey: ['checktransaction_final'],
        queryFn: async () => {
            console.log("Checking address:", address);
            const tx = await nodeManager?.check_address(address!);
            if (!tx) {
                return false
            } else {
                console.log(tx)
                // navigate(`/receive/final?address=${onchainAddress}`)
                return tx
            }
        },
        enabled: !!(nodeManager && address),
        refetchOnWindowFocus: false,
        refetchInterval: 1000
    })

    const { data: lightning } = useQuery({
        queryKey: ['transaction'],
        queryFn: () => {
            console.log("Looking up invoice by hash:", paymentHash);
            return nodeManager?.get_invoice_by_hash(paymentHash!) as Promise<MutinyInvoice>;
        },
        enabled: !!(nodeManager && paymentHash),
    })

    function handleGoHome() {
        navigate("/")
    }

    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            <ScreenMain>
                <>
                    <div />
                    <p className="text-2xl font-light">Got it!</p>
                    {onchain && onchain.txid &&
                        <div className="text-off-white">
                            <a href={mempoolTxUrl(onchain.txid, nodeManager?.get_network())} target="_blank" rel="noreferrer">
                                <h3 className="text-lg font-mono">
                                    {takeN(onchain.txid, 25)}
                                </h3>
                            </a>
                            {onchain?.received !== 0 &&
                                <h3 className="text-lg font-light"><span className="text-green">Received</span> {prettyPrintAmount(onchain.received)} sats</h3>
                            }
                            {onchain?.confirmation_time ?
                                <h4 className="text-sm font-light opacity-50">{prettyPrintTime(onchain.confirmation_time.timestamp)}</h4> :
                                <h4 className="text-sm font-light opacity-50">Unconfirmed</h4>
                            }
                        </div>
                    }
                    {lightning &&
                        <>
                            <div className="text-off-white">
                                <h3 className="text-lg font-mono">
                                    {takeN(lightning.payment_hash, 25)}
                                </h3>
                                <>
                                    {lightning.amount_sats?.valueOf() &&
                                        <h3 className="text-lg font-light"><span className="text-green">Received</span> {prettyPrintAmount(lightning.amount_sats)} sats</h3>
                                    }
                                </>
                            </div>
                        </>
                    }
                    <ActionButton onClick={handleGoHome}>Nice</ActionButton>
                </>
            </ScreenMain>
        </>
    );
}

