import { Link } from "react-router-dom";
import { ReactComponent as CopyIcon } from "../images/icons/copy.svg"

type Props = {
  copyValue: string
}

const Copy: React.FC<Props> = ({ copyValue }) => {

  function handleCopy() {
    navigator.clipboard.writeText(copyValue)
  }

  return (<div onClick={handleCopy} className="h-10 w-10 min-w-10 text-white active:text-half-faint">
    <CopyIcon />
  </div>)

}

export default Copy