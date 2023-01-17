import { ReactNode, useEffect, useRef } from "react";
import { bevelStyle } from "../styles";

interface Props {
    closeOnOutsideClick?: boolean;
    open?: boolean;
    onRequestClose: () => void;
    children?: ReactNode;
}

export default function DialogModal({ closeOnOutsideClick = true, onRequestClose, open = true, children }: Props) {
    const dialogRef = useRef<HTMLDialogElement>(null);
    const lastActiveElement = useRef<unknown | null>(null);
    const firstRender = useRef(true);

    useEffect(() => {
        // prevents calling imperative methods on mount since the polyfill will throw an error since we are not using the `open` attribute
        if (firstRender.current) {
            firstRender.current = false;
        } else {
            const dialogNode = dialogRef.current;
            if (open) {
                lastActiveElement.current = document.activeElement;
                dialogNode?.showModal();
            } else {
                dialogNode?.close();
                if (lastActiveElement.current instanceof HTMLElement) {
                    lastActiveElement.current.focus();
                }
            }
        }
    }, [open])

    function handleOutsideClick(e: React.SyntheticEvent) {
        const dialogNode = dialogRef.current;
        if (closeOnOutsideClick && e.target === dialogNode) {
            onRequestClose();
        }
    }


    useEffect(() => {
        const dialogNode = dialogRef.current
        const handleCancel = (event: Event) => {
            event.preventDefault()
            // onRequestClose()
        }
        dialogNode?.addEventListener('cancel', handleCancel)
        return () => {
            dialogNode?.removeEventListener('cancel', handleCancel)
        }
    }, [])


    return (
        <dialog className={`open:animate-fade-in modal fade backdrop:backdrop-saturate-0 max-w-60vw overflow-scroll max-h-60vh ${bevelStyle()}`} ref={dialogRef} onClick={handleOutsideClick}>
            {children}
        </dialog>
    )
}