import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useNavigate } from "react-router";
import { useContext, useState } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import takeN from "@util/takeN";
import prettyPrintTime from "@util/prettyPrintTime";
import ReceiveLightning from "@components/ReceiveLightning";
import ReceiveOnchain from "@components/ReceiveOnchain";
import { useSearchParams } from "react-router-dom";

export default function ReceiveFinal() {
    let navigate = useNavigate();
    const queryClient = useQueryClient()

    const nodeManager = useContext(NodeManagerContext);

    const [searchParams] = useSearchParams();

    const txid = searchParams.get("txid")
    const paymentHash = searchParams.get("payment_hash")

    const onchain: any = {};
    const lightning: any = {};

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
                <div />
                <p className="text-2xl font-light">Got it!</p>
                {onchain &&
                    <>
                        <div className="text-off-white">
                            <a href={`https://mempool.space/testnet/tx/${onchain.txid}`} target="_blank" rel="noreferrer">
                                <h3 className="text-lg font-mono">
                                    {takeN(onchain.txid, 25)}
                                </h3>
                            </a>
                            {onchain.received !== 0 &&
                                <h3 className="text-lg font-light"><span className="text-green">Received</span> {onchain.received} sats</h3>
                            }
                            {onchain.confirmation_time ?
                                <h4 className="text-sm font-light opacity-50">{prettyPrintTime(onchain.confirmation_time.timestamp)}</h4> :
                                <h4 className="text-sm font-light opacity-50">Unconfirmed</h4>
                            }
                        </div>
                    </>
                }
                {lightning &&
                    <>
                        <div className="text-off-white">
                            <a href={`https://mempool.space/testnet/tx/${onchain.txid}`} target="_blank" rel="noreferrer">
                                <h3 className="text-lg font-mono">
                                    {takeN(onchain.txid, 25)}
                                </h3>
                            </a>
                            {onchain.received !== 0 &&
                                <h3 className="text-lg font-light"><span className="text-green">Received</span> {onchain.received} sats</h3>
                            }
                            {onchain.confirmation_time ?
                                <h4 className="text-sm font-light opacity-50">{prettyPrintTime(onchain.confirmation_time.timestamp)}</h4> :
                                <h4 className="text-sm font-light opacity-50">Unconfirmed</h4>
                            }
                        </div>
                    </>
                }
                <div className='flex justify-start'>
                    <button onClick={handleGoHome}>Nice</button>
                </div>
            </ScreenMain>
        </>
    );
}

