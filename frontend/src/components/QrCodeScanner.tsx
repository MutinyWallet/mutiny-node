import { SendConfirmParams } from "../routes/SendConfirm"
import { detectPaymentType, objectToSearchParams, PaymentType, toastAnything } from "@util/dumb"
import { Html5Qrcode, Html5QrcodeSupportedFormats } from "html5-qrcode"
import { memo, useContext, useEffect, useRef, useState } from "react"
import toast from "react-hot-toast"
import ActionButton from "./ActionButton"
import { useNavigate } from "react-router-dom"
import { NodeManager } from "node-manager";
import { NodeManagerContext } from "./GlobalStateProvider"
import { useSearchParams } from "react-router-dom";
import { inputStyle } from "../styles"
import bip21 from "bip21"

type Props = {
  autoStart?: boolean
  onCodeDetected: (barcodeValue: string) => any
  onValidCode: (data: any) => Promise<void>
}

type UnifiedQrOptions =
  {
    amount?: number;
    lightning?: string;
    label?: string;
    message?: string;
  };

export type MutinyBip21 = { address: string, options: UnifiedQrOptions };

const QrCodeDetectorComponent = ({
  autoStart = true,
  onCodeDetected,
  onValidCode,
}: Props) => {
  const [detecting, setDetecting] = useState<boolean>(autoStart)
  const [errorMessage, setErrorMessage] = useState("")
  const [cameraReady, setCameraReady] = useState<boolean>(false)
  const qrCodeRef = useRef<Html5Qrcode | null>(null)
  const [textFieldDestination, setDestination] = useState("")
  const { nodeManager } = useContext(NodeManagerContext);
  let navigate = useNavigate();
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
    qrCodeRef.current?.stop()
  }

  useEffect(() => {
    if (detecting) {
      Html5Qrcode.getCameras().catch((err) => {
        console.debug("[QRCode Camera error]:", err)
        setErrorMessage("Unable to access camera")
        setDetecting(false)
      })
      qrCodeRef.current =
        qrCodeRef.current ||
        new Html5Qrcode("qrCodeCamera", {
          formatsToSupport: [Html5QrcodeSupportedFormats.QR_CODE],
          verbose: false,
        })
      const detectBarcode = async () => {
        const onScanSuccess = async (decodedText: string) => {
          const parsedResult = onCodeDetected(decodedText)

          console.debug("Qr code parsed result:", parsedResult)

          if (parsedResult) {
            onValidCode(parsedResult)
            await qrCodeRef.current?.stop()
          }
        }

        await qrCodeRef.current?.start(
          { facingMode: "environment" },
          { fps: 10 },
          onScanSuccess,
          () => {
            // Do nothing for invalid scans
          },
        )
        setCameraReady(true)
      }
      detectBarcode()
    }
  }, [detecting, onCodeDetected, onValidCode])

  return (
    <div className="qrContainer">
      {errorMessage && <h1 className="text-2xl font-light">{errorMessage}</h1>}
      <div>
        <div className={cameraReady ? "border-2 border-green" : ""}>
          <div id="qrCodeCamera" />
        </div>
        {!cameraReady &&
          <h1 className="text-2xl font-light">Loading scanner...</h1>
        }
        <input onChange={e => setDestination(e.target.value)} value={textFieldDestination} className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice, pubkey, or address' />
        <ActionButton onClick={() => handleContinue(undefined)}>
          Continue
        </ActionButton>
      </div>
    </div>
  )
}

export const QrCodeScanner = memo(QrCodeDetectorComponent)