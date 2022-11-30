import prettyPrintAmount from "@util/prettyPrintAmount";
import prettyPrintTime from "@util/prettyPrintTime";
import takeN from "@util/takeN";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"
import { DLC_ACCOUNCEMENT_HEX } from "./FinalNewDLC";
import Bear from "@images/48/bear.gif"
import Bull from "@images/48/bull.gif"

function SingleDlc({ bullish }: { bullish: boolean }) {
    return (
        <li className="text-off-white border-b border-green py-2 mb-2 flex gap-2 items-center">
            <div className="w-16 h-16 flex items-center justify-center">
                <img src={bullish ? Bull : Bear} alt="bullish" />
            </div>
            <div>
                <h3 className="text-lg font-mono">
                    {takeN(DLC_ACCOUNCEMENT_HEX, 25)}
                </h3>
                <h3 className="text-lg font-light">
                    {prettyPrintAmount(10000)} sats
                </h3>
                <a href="https://oracle.suredbits.com/announcement/b9dc30042a93daf9d9f3ab9486d7323942b03289b08c946dc14a5522f49242c6" target="_blank" rel="noreferrer">Details</a>
                <h4 className="text-sm font-light opacity-50">Expires {prettyPrintTime(420420)}</h4>
            </div>
        </li>
    )
}

export default function DLCs() {
    const navigate = useNavigate();

    function handleNavNewDLC() {
        navigate("/new-dlc")
    }

    function handleNavJoinDLC() {
        navigate("/join-dlc")
    }

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="DLCs" theme="green" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={true}>
                <div className="flex gap-2 mx-8">
                    <button className="w-full green-button" onClick={handleNavNewDLC}>Create DLC</button>
                    <button className="w-full blue-button" onClick={handleNavJoinDLC}>Join DLC</button>
                </div>
                <ul className="overflow-y-scroll px-8 pb-[12rem] h-full">
                    <SingleDlc bullish={true} key={1} />
                    <SingleDlc bullish={false} key={2} />
                    <SingleDlc bullish={true} key={3} />
                    <SingleDlc bullish={true} key={4} />
                </ul>
            </ScreenMain>
        </>
    )
}

