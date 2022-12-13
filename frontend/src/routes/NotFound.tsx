import Close from "@components/Close";
import PageTitle from "@components/PageTitle";
import ScreenMain from "@components/ScreenMain";
import { useNavigate } from "react-router-dom";

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
            <ScreenMain>
                <div />
                <p className="text-2xl font-light">You weren't supposed to see this!</p>


                <div className='flex justify-start gap-2'>
                    <button onClick={handleCancel}>That Sucks</button>
                </div>
            </ScreenMain>
        </>
    );
}