import { useContext, useState } from "react";
import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { inputStyle } from "../styles";
import toast from "react-hot-toast"
import MutinyToaster from "../components/MutinyToaster";
import { detectPaymentType, PaymentType, toastAnything } from "@util/dumb";
import { NodeManagerContext } from "@components/GlobalStateProvider";

function Send() {
  const nodeManager = useContext(NodeManagerContext);
  let navigate = useNavigate();

  const [destination, setDestination] = useState("")

  async function handleContinue() {
    if (!destination) {
      toast("You didn't paste anything!");
      return
    }

    let paymentType = detectPaymentType(destination)

    if (paymentType === PaymentType.invoice) {
      try {
        let invoice = await nodeManager?.decode_invoice(destination);
        console.table(invoice);
        if (invoice?.amount_sats) {
          navigate(`/send/confirm?destination=${destination}&amount=${invoice?.amount_sats}`)
          return
        }
      } catch (e) {
        console.error(e);
        toastAnything(e);
        return
      }
    }

    if (paymentType === PaymentType.unknown) {
      toast("Couldn't parse that one, buddy")
      return
    }

    navigate(`/send/amount?destination=${destination}`);
  }
  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        <div />
        <input onChange={e => setDestination(e.target.value)} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice, pubkey, or address' />
        <div className='flex justify-start'>
          <button onClick={handleContinue}>Continue</button>
        </div>
      </ScreenMain>
      <MutinyToaster />
    </>
  );
}

export default Send;
