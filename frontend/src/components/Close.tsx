import { useNavigate } from "react-router-dom";
import { ReactComponent as CloseIcon } from "../images/icons/close.svg"

type Props = {
    onClose?: () => void,
    to?: string
}

export default function Close({ onClose, to }: Props) {

    let navigate = useNavigate();

    function handleClose() {
        if (onClose) {
            onClose();
        }

        // onClose could be a cleanup function
        // So we still might want to navigate after
        if (to) {
            navigate(to);
        } else {
            navigate("/");
        }
    }
    return (
        <div className="h-10 w-10 min-w-10 text-white active:text-half-faint" onClick={handleClose}>
            <CloseIcon />
        </div>
    )
}