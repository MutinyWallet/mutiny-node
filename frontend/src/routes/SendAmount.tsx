import { useState } from "react";
import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import toast from "react-hot-toast"
import MutinyToaster from "../components/MutinyToaster";
import { useSearchParams } from "react-router-dom";
import ActionButton from "@components/ActionButton";
import AmountInput from "@components/AmountInput";
import { mainWrapperStyle } from "../styles";

export default function SendAmount() {
  let navigate = useNavigate();

  const [searchParams] = useSearchParams();
  const destination = searchParams.get("destination")

  const [sendAmount, setAmount] = useState("")

  async function handleSubmit(e: React.SyntheticEvent) {
    e.preventDefault()
    const amount = sendAmount.replace(/_/g, "")
    const parsedAmount = parseInt(amount);
    if (!parsedAmount) {
      setAmount('')
      toast("That doesn't look right")
      return
    } else if (parseInt(amount) <= 0) {
      setAmount('')
      toast("You can't send nothing")
      return
    }

    if (destination && typeof parsedAmount === "number") {
      navigate(`/send/confirm?destination=${destination}&amount=${amount}`)
    }
  }
  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>

      <main>
        <form onSubmit={handleSubmit} className={mainWrapperStyle()}>
          <div />
          <div className="flex flex-col gap-4">
            <p className="text-2xl font-light">How much would you like to send?</p>
            <AmountInput amountSats={sendAmount} setAmount={setAmount} accent="green" placeholder="You're the boss" />
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
