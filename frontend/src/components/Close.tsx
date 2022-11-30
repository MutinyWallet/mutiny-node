import { Link } from "react-router-dom";
import { ReactComponent as CloseIcon } from "../images/icons/close.svg"

export default function Close({ route }: { route?: string }) {
    return (<Link to={route ?? "/"} className="h-10 w-10 min-w-10 text-white active:text-half-faint" >
        <CloseIcon />
    </Link>)
}