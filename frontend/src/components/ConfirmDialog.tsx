import DialogModal from "./DialogModal";

interface Props {
    message: string;
    open: boolean;
    onConfirm: () => void;
    onCancel: () => void;
}

export default function ConfirmDialog({ message, open, onConfirm, onCancel }: Props) {
    function handleDialogForm(e: React.SyntheticEvent) {
        e.preventDefault();
        const target = e.target as typeof e.target & { value: string };
        if (target.value === "default") {
            onConfirm();
        } else {
            onCancel();
        }
    }

    return (
        <DialogModal open={open} onRequestClose={onCancel}>
            <form method="dialog" className="flex flex-col gap-4" onSubmit={handleDialogForm}>
                <p className="text-2xl font-light">{message}</p>
                <div className="flex gap-2 w-full justify-end">
                    <button value="default" className="blue-button" onClick={onConfirm}>YES</button>
                    <button value="cancel">NO</button>
                </div>
            </form>
        </DialogModal>
    )

}