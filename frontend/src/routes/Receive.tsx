import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useNavigate } from "react-router";
import { useContext, useState } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";

const TEST_INVOICE = "lntb1u1pwz5w78pp5e8w8cr5c30xzws92v36sk45znhjn098rtc4pea6ertnmvu25ng3sdpywd6hyetyvf5hgueqv3jk6meqd9h8vmmfvdjsxqrrssy29mzkzjfq27u67evzu893heqex737dhcapvcuantkztg6pnk77nrm72y7z0rs47wzc09vcnugk2ve6sr2ewvcrtqnh3yttv847qqvqpvv398"

function Receive() {
    let navigate = useNavigate();

    const nodeManager = useContext(NodeManagerContext);

    const { data: onchainAddress } = useQuery({
        queryKey: ['onchainAddress'],
        queryFn: () => {
            console.log("getting mnemonic...")
            return nodeManager?.get_new_address();
        },
        enabled: !!nodeManager,
    })

    function handleCancel() {
        navigate("/")
    }

    const [isLightning, setIsLightning] = useState(true);
    const [received, setReceived] = useState(false);

    function handlePretend() {
        setReceived(true);
    }

    function handleToggle() {
        setIsLightning(!isLightning);
    }

    function takeN(s: string, n: number): string {
        return `${s.substring(0, n)}…`
    }

    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            {received &&
                <ScreenMain>
                    <div />
                    <p className="text-2xl font-light">Got it!</p>
                    <div className='flex justify-start'>
                        <button onClick={handleCancel}>Nice</button>
                    </div>
                </ScreenMain>
            }
            {!received &&
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
                    </div>

                    <div className='flex justify-start gap-2'>
                        <button onClick={handleCancel}>Cancel</button>
                        <button onClick={handlePretend}>Pretend</button>
                    </div>
                </ScreenMain>
            }
        </>
    );
}

export default Receive;
