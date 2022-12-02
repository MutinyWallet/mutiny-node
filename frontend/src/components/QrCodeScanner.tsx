import { Html5Qrcode, Html5QrcodeSupportedFormats } from "html5-qrcode"
import { memo, useEffect, useRef, useState } from "react"

type Props = {
  autoStart?: boolean
  onCodeDetected: (barcodeValue: string) => any
  onValidCode: (data: any) => Promise<void>
}

const QrCodeDetectorComponent = ({
  autoStart = true,
  onCodeDetected,
  onValidCode,
}: Props) => {
  const [detecting, setDetecting] = useState<boolean>(autoStart)
  const [errorMessage, setErrorMessage] = useState("")
  const [cameraReady, setCameraReady] = useState<boolean>(false)
  const qrCodeRef = useRef<Html5Qrcode | null>(null)

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
    <div>
      {errorMessage && <h1 className="text-2xl font-light">{errorMessage}</h1>}
      <div>
        <div className={cameraReady ? "border-2 border-green" : ""}>
          <div id="qrCodeCamera" />
        </div>
        {!cameraReady &&
          <h1 className="text-2xl font-light">Loading scanner...</h1>
        }
      </div>
    </div>
  )
}

export const QrCodeScanner = memo(QrCodeDetectorComponent)