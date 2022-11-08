import { Link } from "react-router-dom";

type Props = {
  copyValue: string
}

const Copy: React.FC<Props> = ({ copyValue }) => {

  function handleCopy() {
    navigator.clipboard.writeText(copyValue)
  }

  return (<div onClick={handleCopy} className="h-10 w-10 min-w-10 text-white" >
    <svg fill="none" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
      <path d="M4 2h11v2H6v13H4V2zm4 4h12v16H8V6zm2 2v12h8V8h-8z" fill="currentColor" />
    </svg>
  </div>)

}

export default Copy