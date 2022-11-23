import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import {useContext, useState} from "react";
import {useQuery, useQueryClient} from "@tanstack/react-query";
import ReceiveLightning from "@components/ReceiveLightning";
import ReceiveOnchain from "@components/ReceiveOnchain";
import {NodeManagerContext} from "@components/GlobalStateProvider";

function Receive() {
    let navigate = useNavigate();
    const nodeManager = useContext(NodeManagerContext);
    const queryClient = useQueryClient()

    function handleCancel() {
        navigate("/")
    }

    const { data: invoice } = useQuery({
        queryKey: ['lightninginvoice'],
        queryFn: () => {
            console.log("Getting new invoice...")
            return nodeManager?.create_invoice(BigInt(1000), "testing 123");
        },
        enabled: !!nodeManager,
        // Don't want a new address each time they focus the window
        refetchOnWindowFocus: false
    })

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
            <ScreenMain>
                <div />
                <div className="flex gap-2">
                    <button onClick={handleToggle} disabled={!isLightning} className={isLightning ? "secondary" : "toggle"}>On-chain</button>
                    <button onClick={handleToggle} disabled={isLightning} className={!isLightning ? "secondary" : "toggle"}>Lightning</button>
                </div>

                <div className="flex flex-col items-start gap-4">
                    {isLightning ? <ReceiveLightning invoice={invoice} /> : <ReceiveOnchain onchainAddress={onchainAddress} />}
                </div>

                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>Cancel</button>
                </div>
            </ScreenMain>
        </>
    );
}

export default Receive;
