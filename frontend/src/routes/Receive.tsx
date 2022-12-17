import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useNavigate } from "react-router";
import { useState } from "react";
import { inputStyle } from "../styles";
import { objectToSearchParams } from "@util/dumb";
import { ReceiveParams } from "../routes/ReceiveQR";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import ActionButton from "@components/ActionButton";
import MutinyToaster from "@components/MutinyToaster";

function Receive() {
    let navigate = useNavigate();

    const [amount, setAmount] = useState("")
    const [description, setDescription] = useState("")
    const queryClient = useQueryClient()

    async function handleContinue() {
        if (!amount || typeof parseInt(amount) !== "number") {
            toast("That doesn't look right")
            return
        } else if (parseInt(amount) <= 0) {
            setAmount('')
            toast("You can't receive nothing")
            return
        }
        if (parseInt(amount) > 0) {
            const params = objectToSearchParams<ReceiveParams>({ amount, description })
            // Important! Otherwise we might see a stale bip21 code
            queryClient.invalidateQueries({ queryKey: ['bip21'] })
            navigate(`/receive/qr?${params}`)
        }
    }

    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="Receive" theme="blue"></PageTitle>
                <Close />
            </header>
            <ScreenMain>
                <div />
                <p className="text-2xl font-light">Want some sats?</p>
                <div className="flex flex-col gap-4">
                    <input onChange={e => setAmount(e.target.value)} value={amount} className={`w-full ${inputStyle({ accent: "blue" })}`} type="number" min={0} placeholder='How much? (optional)' />
                    <input onChange={(e) => setDescription(e.target.value)} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='What for? (optional)' />
                </div>
                <ActionButton onClick={() => handleContinue()}>
                    Continue
                </ActionButton>
            </ScreenMain>
            <MutinyToaster />
        </>
    );
}

export default Receive;
