import { Html5Qrcode, Html5QrcodeSupportedFormats } from "html5-qrcode"
import { memo, useEffect, useRef, useState } from "react"

type Props = {
  autoStart?: boolean
  startText: string
  stopText: string
  onCodeDetected: (barcodeValue: string) => any
  onValidCode: (data: any) => Promise<void>
}

const QrCodeDetectorComponent = ({
  autoStart = false,
  startText,
  stopText,
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

          console.log("parsedResult: ", parsedResult)

          if (parsedResult) {
            onValidCode(parsedResult)
            await qrCodeRef.current?.stop()
            setDetecting(false)
          }
        }

        await qrCodeRef.current?.start(
          { facingMode: "environment" },
          { fps: 10, qrbox: 400 },
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

  const startDetecting = async () => {
    setDetecting(true)
  }

  const stopDetecting = async () => {
    await qrCodeRef.current?.stop()
    setDetecting(false)
  }

  return (
    <div className="qrcode-detector">
      {errorMessage && <div className="error">{errorMessage}</div>}
      {detecting ? (
        <div className="qrcode-camera">
          <div id="qrCodeCamera" />
          {cameraReady ? (
            <div className="scan-stop link" onClick={stopDetecting}>
              {stopText}
            </div>
          ) : (
            <h1>loading...</h1>
          )}
        </div>
      ) : (
        <div className="scan-start link" onClick={startDetecting}>
          <h1>qr icon</h1>
          {startText}
        </div>
      )}
    </div>
  )
}

export const QrCodeScanner = memo(QrCodeDetectorComponent)