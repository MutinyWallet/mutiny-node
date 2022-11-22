import { useContext } from "react";
import { Link } from "react-router-dom";
import { ReactComponent as MoreIcon } from "../images/icons/more.svg"
import { ManagerRouteContext } from "./ManagerRouteProvider";

export default function More() {
    const { managerRoute } = useContext(ManagerRouteContext);
    return (<Link to={`/manager/${managerRoute}`} className="h-10 w-10 min-w-10 text-white active:text-half-faint" >
        <MoreIcon />
    </Link>)
}