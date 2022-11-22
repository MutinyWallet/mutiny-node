import { NodeManagerContext } from "@components/GlobalStateProvider";
import { useQuery } from "@tanstack/react-query";
import { useContext } from "react";
import Close from "../components/Close"
import PageTitle from "../components/PageTitle"
import ScreenMain from "../components/ScreenMain"

function Settings() {
    const nodeManager = useContext(NodeManagerContext);

    const { isLoading, data: words } = useQuery({
        queryKey: ['words'],
        queryFn: () => {
            console.log("Getting mnemonic...")
            return nodeManager?.show_seed();
        },
        enabled: !!nodeManager,
    })

    return (
        <>
            <header className='px-8 pt-8 flex justify-between items-center'>
                <PageTitle title="Settings" theme="red" />
                <Close />
            </header>
            <ScreenMain padSides={false} wontScroll={true}>
                <div className="flex-1 overflow-y-scroll px-8 pb-[12rem]">
                    <p className="text-2xl font-light">Write down these words or you'll die!</p>
                    <pre>
                        <code>{isLoading ? "..." : words}</code>
                    </pre>
                </div>
            </ScreenMain>
        </>
    )
}

export default Settings