import { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useSearchParams } from "react-router-dom";
import { NodeManagerContext } from "@components/GlobalStateProvider";
import toast from "react-hot-toast";
import { detectPaymentType, getFirstNode, PaymentType, toastAnything } from "@util/dumb";
import MutinyToaster from "@components/MutinyToaster";

function SendConfirm() {
  const nodeManager = useContext(NodeManagerContext);

  const [sentOnchain, setSentOnchain] = useState(false)
  const [sentKeysend, setSentKeysend] = useState(false)
  const [description, setDescription] = useState("")
  const [searchParams] = useSearchParams();
  const [txid, setTxid] = useState<string>();

  const [loading, setLoading] = useState(false);

  const amount = searchParams.get("amount")
  const destination = searchParams.get("destination")

  searchParams.forEach((value, key) => {
    console.log(key, value);
  });

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
          setTxid(txid)
          setSentOnchain(true);
        } else if (paymentType === PaymentType.keysend) {
          let myNode = await getFirstNode(nodeManager!);
          await nodeManager?.keysend(myNode, destination, amountInt)
          setSentKeysend(true);
        }
      }
    } catch (e: unknown) {
      console.error(e);
      toastAnything(e);
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
      {loading && <ScreenMain>
        <p className="text-2xl font-light">Sending...</p>
      </ScreenMain>
      }
      {!loading && sentKeysend &&
        <ScreenMain>
          <div />
          <p className="text-2xl font-light">Sent!</p>
          <div className='flex justify-start'>
            <button onClick={handleNice}>Nice</button>
          </div>
        </ScreenMain>
      }
      {!loading && sentOnchain &&
        <ScreenMain>
          <div />
          <p className="text-2xl font-light">Sent!</p>
          <dl>
            <div className="rounded border p-2 my-2 font-mono break-words">
              <dt>TXID</dt>
              <dd>
                {txid}
              </dd>
            </div>
          </dl>
          <div className='flex justify-start'>
            <button onClick={handleNice}>Nice</button>
          </div>
        </ScreenMain>
      }
      {!loading && !sentOnchain && !sentKeysend &&
        <ScreenMain>
          <div />
          <p className="text-2xl font-light">How does this look to you?</p>
          <dl>
            <div className="rounded border p-2 my-2">
              <dt>Who</dt>
              <dd className="font-mono break-words">{destination}</dd>
            </div>
            <div className="rounded border p-2 my-2">
              <dt>How Much</dt>
              <dd>{amount} sat</dd>
            </div>
            <div className="rounded border p-2 my-2 flex flex-col">
              <dt>What For</dt>
              <dd>{description}</dd>
              <button className="self-end" onClick={() => setDescription("for farts")}>Edit</button>
            </div>
          </dl>
          <div className='flex justify-start'>
            <button onClick={handleSend}>Send</button>
          </div>
          <MutinyToaster />
        </ScreenMain>
      }
    </>

  );
}

export default SendConfirm;
