import { useState } from "react";
import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";
import toast from "react-hot-toast"
import MutinyToaster from "../components/MutinyToaster";

function Send() {
  let navigate = useNavigate();

  const [destination, setDestination] = useState("")

  const [showAmountInput, setShowAmountInput] = useState(false)
  const [amount, setAmount] = useState("")

  function handleContinue() {
    if (!destination) {
      toast("You didn't paste anything!");
    }

    if (destination && !amount) {
      setShowAmountInput(true)
      return
    }

    if (destination && amount) {
      navigate(`/send/confirm?destination=${destination}&amount=${amount}`)
    }
  }
  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        <div />
        {!showAmountInput && <input onChange={e => setDestination(e.target.value)} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice or address' />}
        {showAmountInput &&
          <div className="flex flex-col gap-4">
            <p className="text-2xl font-light">How much would you like to send?</p>
            <input onChange={e => setAmount(e.target.value)} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='sats' />
          </div>
        }
        <div className='flex justify-start'>
          <button onClick={handleContinue}>Continue</button>
        </div>
      </ScreenMain>
      <MutinyToaster />
    </>
  );
}

export default Send;
