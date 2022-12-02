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
import bip21 from "bip21"
import { NodeManager } from "node-manager";
import { QrCodeScanner } from "@components/QrCodeScanner";

type UnifiedQrOptions =
  {
    amount?: number;
    lightning?: string;
    label?: string;
    message?: string;
  };

type Bip21 = { address: string, options: UnifiedQrOptions };

function Send() {
  const nodeManager = useContext(NodeManagerContext);
  let navigate = useNavigate();

  const [textFieldDestination, setDestination] = useState("")

  async function navigateForInvoice(invoiceStr: string) {
    try {
      let invoice = await nodeManager?.decode_invoice(invoiceStr);
      console.table(invoice);
      if (invoice?.amount_sats && Number(invoice?.amount_sats) > 0) {
        navigate(`/send/confirm?destination=${invoiceStr}&amount=${invoice?.amount_sats}`)
        return
      } else {
        navigate(`/send/amount?destination=${invoiceStr}`)
        return
      }
    } catch (e) {
      console.error(e);
      toastAnything(e);
    }
  }

  async function handleContinue(qrRead?: string) {
    let destination: string = qrRead || textFieldDestination;
    if (!destination) {
      toast("You didn't paste anything!");
      return
    }

    let paymentType = detectPaymentType(destination)

    if (paymentType === PaymentType.invoice) {
      await navigateForInvoice(destination)
      return
    } else if (paymentType === PaymentType.bip21) {
      const { address, options } = bip21.decode(destination) as Bip21;
      if (options?.lightning) {
        await navigateForInvoice(options.lightning)
        return
      } else if (options?.amount) {
        try {
          const amount = NodeManager.convert_btc_to_sats(options.amount ?? 0.0);
          if (!amount) {
            throw new Error("Failed to convert BTC to sats")
          }
          if (options.label) {
            navigate(`/send/confirm?destination=${address}&amount=${amount}&description=${options.label}`)
          } else {
            navigate(`/send/confirm?destination=${address}&amount=${amount}`)
          }
          return
        } catch (e) {
          console.error(e)
          toastAnything(e);
          return
        }
      } else {
        navigate(`/send/amount?destination=${address}`)
        return
      }
    }

    if (paymentType === PaymentType.unknown) {
      toast("Couldn't parse that one, buddy")
      return
    }


    navigate(`/send/amount?destination=${destination}`);
  }

  function onCodeDetected(barcodeValue: string): string | undefined {
    let paymentType = detectPaymentType(barcodeValue)

    if (paymentType !== PaymentType.unknown) {
      return barcodeValue
    } else {
      toastAnything("Sorry I don't know what that is")
    }
  }

  async function onValidCode(data: string | undefined) {
    if (!data) {
      return
    }
    await handleContinue(data)
  }

  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        <QrCodeScanner onValidCode={onValidCode} onCodeDetected={onCodeDetected} />
        <input onChange={e => setDestination(e.target.value)} value={textFieldDestination} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice, pubkey, or address' />
        <div className='flex justify-start'>
          <button onClick={() => handleContinue(undefined)}>Continue</button>
        </div>
      </ScreenMain>
      <MutinyToaster />
    </>
  );
}

export default Send;
