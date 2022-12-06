import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useSearchParams } from "react-router-dom";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import toast from "react-hot-toast";
import { detectPaymentType, errorAsString, getFirstNode, PaymentType, toastAnything } from "@util/dumb";
import MutinyToaster from "@components/MutinyToaster";
import { useQuery } from "@tanstack/react-query";
import prettyPrintAmount from "@util/prettyPrintAmount";
import ActionButton from "@components/ActionButton";
import SimpleText from "@components/SimpleText";

export type SendConfirmParams = {
  amount?: string;
  destination?: string;
  description?: string;
  all?: string;
}

function SendConfirm() {
  const nodeManager = useContext(NodeManagerContext);

  const [searchParams] = useSearchParams();
  const [failed, setFailed] = useState(false)
  const [failureReason, setFailureReason] = useState("")

  const [loading, setLoading] = useState(false);

  const amount = searchParams.get("amount")
  const destination = searchParams.get("destination")
  const description = searchParams.get("description")
  const sendAll = searchParams.get("all") === "true"

  const { data: invoice } = useQuery({
    queryKey: ['lightninginvoice'],
    queryFn: () => {
      console.log("Decoding invoice...")
      return nodeManager?.decode_invoice(destination!);
    },
    enabled: !!(destination && nodeManager && detectPaymentType(destination) === PaymentType.invoice),
    refetchOnWindowFocus: false
  })

  async function handleSend() {
    setLoading(true);
    try {
      if (destination && amount) {
        let amountInt = BigInt(amount);
        if (typeof amountInt !== "bigint") {
          toast("Couldn't parse amount")
          throw new Error("Invalid amount")
        }

        const paymentType = detectPaymentType(destination);

        if (paymentType === PaymentType.onchain) {
          const txid = await nodeManager?.send_to_address(destination, amountInt);
          await nodeManager?.sync();
          navigate(`/send/final?txid=${txid}`)
        } else if (paymentType === PaymentType.keysend) {
          let myNode = await getFirstNode(nodeManager!);
          await nodeManager?.keysend(myNode, destination, amountInt)
          navigate(`/send/final`)
        } else if (paymentType === PaymentType.invoice) {
          let myNode = await getFirstNode(nodeManager!);
          let invoice = await nodeManager?.decode_invoice(destination);
          if (invoice?.amount_sats && Number(invoice?.amount_sats) > 0) {
            await nodeManager?.pay_invoice(myNode, destination)
          } else {
            await nodeManager?.pay_invoice(myNode, destination, BigInt(amount))
          }
          navigate(`/send/final`)
        }
      } else if (destination && sendAll) {
        const paymentType = detectPaymentType(destination);

        if (paymentType === PaymentType.onchain) {
          const txid = await nodeManager?.sweep_wallet(destination);
          await nodeManager?.sync();
          navigate(`/send/final?txid=${txid}`)
        } else {
          throw new Error(`Cannot send all with payment type: ${paymentType}`)
        }
      }
    } catch (e: unknown) {
      console.error(e);
      toastAnything(e);
      setFailureReason(errorAsString(e));
      setFailed(true);
    }

    setLoading(false);
  }

  let navigate = useNavigate();

  function handleNice() {
    navigate("/")
  }

  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Confirm" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        {loading && <>
          <div />
          <SimpleText>Sending...</SimpleText>
          <div />
        </>
        }

        {failed && <>
          <div />
          <SimpleText>Payment failed: {failureReason}</SimpleText>
          <ActionButton onClick={handleNice}>Dangit</ActionButton>
        </>}

        {!failed && !loading && invoice &&
          <>
            <div />
            <SimpleText>How does this look to you?</SimpleText>
            <dl>
              {invoice.payee_pubkey ?
                <div className="rounded border p-2 my-2">
                  <dt>Who</dt>
                  <dd className="font-mono break-words">{invoice.payee_pubkey}</dd>
                </div>
                :
                <div className="rounded border p-2 my-2">
                  <dt>Payment Hash</dt>
                  <dd className="font-mono break-words">{invoice.payment_hash}</dd>
                </div>
              }

              <div className="rounded border p-2 my-2">
                <>
                  <dt>How Much</dt>
                  {amount &&
                    <dd>{prettyPrintAmount(parseInt(amount!))} sats</dd>
                  }
                  {(!amount && invoice.amount_sats) &&
                    <dd>{prettyPrintAmount(invoice.amount_sats)} sats</dd>
                  }
                </>
              </div>
              {invoice.description &&
                <div className="rounded border p-2 my-2 flex flex-col">
                  <dt>What For</dt>
                  <dd>{invoice.description}</dd>
                  <button className="self-end" onClick={() => console.log("Unimplemented")}>Edit</button>
                </div>
              }
            </dl>
            <ActionButton onClick={handleSend}>Send</ActionButton>
          </>
        }

        {!failed && !loading && !invoice &&
          <>
            <div />
            <SimpleText>How does this look to you?</SimpleText>
            <dl>
              <div className="rounded border p-2 my-2">
                <dt>Who</dt>
                <dd className="font-mono break-words">{destination}</dd>
              </div>
              {amount &&
                <div className="rounded border p-2 my-2">
                  <dt>How Much</dt>
                  <dd>{prettyPrintAmount(parseInt(amount))} sats</dd>
                </div>
              }
              {(!amount && sendAll) &&
                <div className="rounded border p-2 my-2">
                  <dt>How Much</dt>
                  <dd>All</dd>
                </div>
              }
              {description &&
                <div className="rounded border p-2 my-2 flex flex-col">
                  <dt>What For</dt>
                  <dd>{description}</dd>
                  <button className="self-end" onClick={() => console.log("Unimplemented")}>Edit</button>
                </div>
              }
            </dl>
            <ActionButton onClick={handleSend}>
              Send
            </ActionButton>
          </>
        }

      </ScreenMain>
      <MutinyToaster />
    </>

  );
}

export default SendConfirm;
