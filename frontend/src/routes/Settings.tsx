import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

const WORDS = "apart main neck basket measure pottery vote fuel fame chuckle wink absurd"

function Settings() {
    return (
        <div className="h-full">
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Settings" theme="red" />
                <Close />
            </header>
            <ScreenMain padSides={false}>
                <div className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    <p className="text-2xl font-light">Write down these words or you'll die!</p>
                    <pre>
                        <code>{WORDS}</code>
                    </pre>
                </div>
            </ScreenMain>
        </div>
    )
}

export default Settings