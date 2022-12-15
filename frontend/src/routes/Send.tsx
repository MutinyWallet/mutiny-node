import { useContext, useState } from "react";
import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import toast from "react-hot-toast"
import MutinyToaster from "../components/MutinyToaster";
import { detectPaymentType, objectToSearchParams, PaymentType, toastAnything } from "@util/dumb";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import bip21 from "bip21"
import { NodeManager } from "node-manager";
import { QrCodeScanner } from "@components/QrCodeScanner";
import { SendConfirmParams } from "./SendConfirm";
import { useSearchParams } from "react-router-dom";

type UnifiedQrOptions =
  {
    amount?: number;
    lightning?: string;
    label?: string;
    message?: string;
  };

export type MutinyBip21 = { address: string, options: UnifiedQrOptions };

function Send() {
  const { nodeManager } = useContext(NodeManagerContext);
  let navigate = useNavigate();

  const [textFieldDestination] = useState("")

  const [searchParams] = useSearchParams();
  const sendAll = searchParams.get("all")

  async function navigateForInvoice(invoiceStr: string) {
    try {
      let invoice = await nodeManager?.decode_invoice(invoiceStr);
      console.table(invoice);
      if (invoice?.amount_sats && Number(invoice?.amount_sats) > 0) {
        const params = objectToSearchParams<SendConfirmParams>({ destination: invoiceStr, amount: invoice?.amount_sats.toString(), description: invoice?.description || undefined })
        navigate(`/send/confirm?${params}`)
      } else {
        const params = objectToSearchParams<SendConfirmParams>({ destination: invoiceStr, description: invoice?.description || undefined })
        navigate(`/send/amount?${params}`)
      }
    } catch (e) {
      console.error(e);
      toastAnything(e);
    }
  }

  async function navigateForBip21(bip21String: string) {
    const { address, options } = bip21.decode(bip21String) as MutinyBip21;
    if (options?.lightning) {
      await navigateForInvoice(options.lightning)
    } else if (options?.amount) {
      try {
        const amount = NodeManager.convert_btc_to_sats(options.amount ?? 0.0);
        if (!amount) {
          throw new Error("Failed to convert BTC to sats")
        }
        if (options.label) {
          const params = objectToSearchParams<SendConfirmParams>({ destination: address, amount: amount.toString(), description: options.label })
          navigate(`/send/confirm?${params}`)
        } else {
          const params = objectToSearchParams<SendConfirmParams>({ destination: address, amount: amount.toString() })
          navigate(`/send/confirm?${params}`)
        }
      } catch (e) {
        console.error(e)
        toastAnything(e);
      }
    }
  }

  async function handleContinue(qrRead?: string) {
    let destination: string = qrRead || textFieldDestination;
    if (!destination) {
      toast("You didn't paste anything!");
      return
    }

    let paymentType = detectPaymentType(destination)

    if (paymentType === PaymentType.unknown) {
      toast("Couldn't parse that one, buddy")
      return
    }

    if (paymentType === PaymentType.invoice) {
      await navigateForInvoice(destination)
    } else if (paymentType === PaymentType.bip21) {
      await navigateForBip21(destination)
    } else if (paymentType === PaymentType.onchain) {
      if (sendAll === "true") {
        const params = objectToSearchParams<SendConfirmParams>({ destination, all: "true" })
        navigate(`/send/confirm?${params}`)
      } else {
        const params = objectToSearchParams<SendConfirmParams>({ destination })
        navigate(`/send/amount?${params}`)
      }
    }
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
      </ScreenMain>
      <MutinyToaster />
    </>
  );
}

export default Send;
