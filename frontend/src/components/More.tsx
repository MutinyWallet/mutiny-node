import { Link } from "react-router-dom";
import { ReactComponent as MoreIcon } from "../images/icons/more.svg"

export default function More() {
    return (<Link to="/manager/transactions" className="h-10 w-10 min-w-10 text-white active:text-half-faint" >
        <MoreIcon />
    </Link>)
}