import Close from "@components/Close";
import PageTitle from "@components/PageTitle";
import { useNavigate } from "react-router-dom";
import { mainWrapperStyle } from "../styles";

export default function NotFound() {
    let navigate = useNavigate();

    function handleCancel() {
        navigate("/")
    }
    return (
        <>
            <header className='p-8 flex justify-between items-center'>
                <PageTitle title="404 Not Found" theme="red"></PageTitle>
                <Close />
            </header>
            <main className={mainWrapperStyle()}>
                <div />
                <p className="text-2xl font-light">You weren't supposed to see this!</p>


                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>That Sucks</button>
                </div>
            </main>
        </>
    );
}