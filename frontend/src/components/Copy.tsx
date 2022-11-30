import { toastAnything } from "@util/dumb"
import toast from "react-hot-toast"
import { ReactComponent as CopyIcon } from "../images/icons/copy.svg"

type Props = {
  copyValue: string
}

const Copy: React.FC<Props> = ({ copyValue }) => {

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(copyValue)
      toast("Copied!")
    } catch (e) {
      console.error(e)
      toastAnything(e)
    }
  }

  return (<div onClick={handleCopy} className="h-10 w-10 min-w-10 text-white active:text-half-faint">
    <CopyIcon />
  </div>)

}

export default Copy