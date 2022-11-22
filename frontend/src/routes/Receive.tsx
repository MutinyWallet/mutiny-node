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

const TEST_INVOICE = "lntb1u1pwz5w78pp5e8w8cr5c30xzws92v36sk45znhjn098rtc4pea6ertnmvu25ng3sdpywd6hyetyvf5hgueqv3jk6meqd9h8vmmfvdjsxqrrssy29mzkzjfq27u67evzu893heqex737dhcapvcuantkztg6pnk77nrm72y7z0rs47wzc09vcnugk2ve6sr2ewvcrtqnh3yttv847qqvqpvv398"

function Receive() {
    let navigate = useNavigate();
    const queryClient = useQueryClient()

    const nodeManager = useContext(NodeManagerContext);

    const { data: onchainAddress } = useQuery({
        queryKey: ['onchainAddress'],
        queryFn: () => {
            console.log("Getting new address...")
            return nodeManager?.get_new_address();
        },
        enabled: !!nodeManager,
        // Don't want a new address each time they focus the window
        refetchOnWindowFocus: false
    })

    const { isLoading: isCheckingAddress, data: transaction } = useQuery({
        queryKey: ['checktransaction'],
        queryFn: async () => {
            console.log("Checking address:", onchainAddress);
            const tx = await nodeManager?.check_address(onchainAddress!);
            if (!tx) {
                return false
            } else {
                console.log(tx)
                return tx
            }
        },
        enabled: !!onchainAddress,
        refetchInterval: 1000
    })

    function handleCancel() {
        navigate("/")
    }

    const [isLightning, setIsLightning] = useState(true);

    function handleToggle() {
        setIsLightning(!isLightning);
        queryClient.invalidateQueries(['onchainaddress'])

    }

    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            {transaction &&
                <ScreenMain>
                    <div />
                    <p className="text-2xl font-light">Got it!</p>
                    <div className="text-off-white">
                        <a href={`https://mempool.space/testnet/tx/${transaction.txid}`} target="_blank" rel="noreferrer">
                            <h3 className="text-lg font-mono">
                                {takeN(transaction.txid, 25)}
                            </h3>
                        </a>
                        {transaction.received !== 0 &&
                            <h3 className="text-lg font-light"><span className="text-green">Received</span> {transaction.received} sats</h3>
                        }
                        {transaction.confirmation_time ?
                            <h4 className="text-sm font-light opacity-50">{prettyPrintTime(transaction.confirmation_time.timestamp)}</h4> :
                            <h4 className="text-sm font-light opacity-50">Unconfirmed</h4>
                        }
                    </div>
                    <div className='flex justify-start'>
                        <button onClick={handleCancel}>Nice</button>
                    </div>
                </ScreenMain>
            }
            {!transaction &&
                <ScreenMain>
                    <div />
                    <div className="flex gap-2">
                        <button onClick={handleToggle} disabled={!isLightning} className={isLightning ? "secondary" : "toggle"}>On-chain</button>
                        <button onClick={handleToggle} disabled={isLightning} className={!isLightning ? "secondary" : "toggle"}>Lightning</button>
                    </div>
                    <div className="flex flex-col items-start gap-4">
                        <div className="bg-[#ffffff] p-4">
                            {isLightning ? <QRCode value={TEST_INVOICE} /> :
                                (onchainAddress && <QRCode value={onchainAddress} />)}
                        </div>
                        <div className="flex items-center gap-2 w-full">
                            {/* <p className="text-lg font-mono font-light break-all"> */}
                            <pre className="flex-1">
                                <code className="break-all whitespace-nowrap overflow-hidden overflow-ellipsis">
                                    {isLightning ? takeN(TEST_INVOICE, 28) : (onchainAddress && takeN(onchainAddress, 28))}
                                </code>
                            </pre>
                            <div className="flex-0">
                                {isLightning ? <Copy copyValue={TEST_INVOICE} /> :
                                    (onchainAddress && <Copy copyValue={onchainAddress} />)}
                            </div>
                        </div>
                        {!isLightning &&
                            <p className="text-2xl font-light transition-all">{isCheckingAddress ? "Checking" : "Checking..."}</p>
                        }

                    </div>

                    <div className='flex justify-start gap-2'>
                        <button onClick={handleCancel}>Cancel</button>
                    </div>
                </ScreenMain>
            }
        </>
    );
}

export default Receive;
