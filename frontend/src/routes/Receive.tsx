import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import { useNavigate } from "react-router";
import { useState } from "react";
import { inputStyle, mainWrapperStyle } from "../styles";
import { objectToSearchParams } from "@util/dumb";
import { ReceiveParams } from "../routes/ReceiveQR";
import { useQueryClient } from "@tanstack/react-query";
import toast from "react-hot-toast";
import ActionButton from "@components/ActionButton";
import MutinyToaster from "@components/MutinyToaster";
import AmountInput from "@components/AmountInput";

function Receive() {
    let navigate = useNavigate();

    const [receiveAmount, setAmount] = useState("")
    const [description, setDescription] = useState("")
    const queryClient = useQueryClient()

    async function handleSubmit(e: React.SyntheticEvent) {
        e.preventDefault()
        const amount = receiveAmount.replace(/_/g, "")
        if (amount.match(/\D/)) {
            setAmount('')
            toast("That doesn't look right")
            return
        }
        if (amount.length === 0 || amount.match(/^\d+$/)) {
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
            <main>
                <form onSubmit={handleSubmit} className={mainWrapperStyle()}>
                    <div />
                    <p className="text-2xl font-light">Want some sats?</p>
                    <div className="flex flex-col gap-4">
                        <AmountInput amountSats={receiveAmount} setAmount={setAmount} accent="blue" placeholder="How much? (optional)" />
                        <input onChange={(e) => setDescription(e.target.value)} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='What for? (optional)' />
                    </div>
                    <ActionButton>
                        Continue
                    </ActionButton>
                </form>
            </main>
            <MutinyToaster />
        </>
    );
}

export default Receive;
