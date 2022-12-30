import { toast } from "react-hot-toast"
import { ReactComponent as CopyIcon } from "../images/icons/copy.svg"
import MutinyToaster from "./MutinyToaster"

type Props = {
  copyValue: string
}

const Copy: React.FC<Props> = ({ copyValue }) => {

  function handleCopy() {
    navigator.clipboard.writeText(copyValue)
    toast('Copied to Clipboard!')
  }

  return (<div onClick={handleCopy} className="h-10 w-10 min-w-10 text-white active:text-half-faint">
    <CopyIcon />
    <MutinyToaster />
  </div>)

}

export default Copy