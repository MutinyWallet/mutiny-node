import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import { useContext, useState } from "react";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQueryClient } from "@tanstack/react-query";
import ReceiveLightning from "@components/ReceiveLightning";
import ReceiveOnchain from "@components/ReceiveOnchain";

function Receive() {
    let navigate = useNavigate();
    const queryClient = useQueryClient()

    const nodeManager = useContext(NodeManagerContext);

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
            <ScreenMain>
                <div />
                <div className="flex gap-2">
                    <button onClick={handleToggle} disabled={!isLightning} className={isLightning ? "secondary" : "toggle"}>On-chain</button>
                    <button onClick={handleToggle} disabled={isLightning} className={!isLightning ? "secondary" : "toggle"}>Lightning</button>
                </div>

                <div className="flex flex-col items-start gap-4">
                    {isLightning ? <ReceiveLightning /> : <ReceiveOnchain />}
                </div>

                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>Cancel</button>
                </div>
            </ScreenMain>
        </>
    );
}

export default Receive;
