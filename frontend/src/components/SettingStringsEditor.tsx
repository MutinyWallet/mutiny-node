import { toastAnything } from "@util/dumb";
import { ChangeEvent, useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import { inputStyle } from "../styles";
import { getExistingSettings, NodeManagerContext, NodeManagerSettingStrings } from "./GlobalStateProvider";

export default function SettingStringsEditor() {
    let navigate = useNavigate();
    const { setup } = useContext(NodeManagerContext);

    const [nodeManagerSettings, setNodeManagerSettings] = useState<NodeManagerSettingStrings>(getExistingSettings());
    const [selectedNetwork, setSelectedNetwork] = useState(nodeManagerSettings.network);

    async function handleSaveSettings() {
        try {
            let existingNetwork = getExistingSettings().network;
            if (existingNetwork !== nodeManagerSettings.network) {
                if (window.confirm("Changing networks will delete your node's state. This can't be undone!")) {
                    localStorage.clear();
                    window.location.reload();
                }
            }
            await setup(nodeManagerSettings);
            navigate("/")
        } catch (e) {
            console.error(e)
            toastAnything(e)
        }
    }

    const handleInputChange = (name: string) => (e: ChangeEvent<HTMLInputElement>) => {
        const { value } = e.target;
        console.log("typing")
        setNodeManagerSettings({
            ...nodeManagerSettings,
            [name]: value,
        });
    };

    const handleSelectChange = (name: string) => (e: React.ChangeEvent<HTMLSelectElement>) => {
        setSelectedNetwork(e.target.value)
        setNodeManagerSettings({
            ...nodeManagerSettings,
            [name]: e.target.value,
        });
    };

    return (
        <>
            <p className="text-2xl font-light">Don't trust us! Use your own servers to back Mutiny</p>
            <div className="flex flex-col gap-2 w-full">
                <h3 className="text-lg font-light uppercase mt-2">Network</h3>
                <form>
                    <select onChange={handleSelectChange("network")} className={`w-full text-black bg-white text-xl ${inputStyle({ accent: "blue" })}`} name='' value={selectedNetwork} placeholder="Network">
                        <option className="text-base" value="bitcoin">Mainnet</option>
                        <option className="text-base" value="testnet">Testnet</option>
                        <option className="text-base" value="signet">Signet</option>
                        <option className="text-base" value="regtest">Regtest</option>
                    </select>
                </form>
                <h3 className="text-lg font-light uppercase mt-2">Esplora</h3>
                <input onChange={handleInputChange("esplora")} defaultValue={nodeManagerSettings.esplora} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Esplora' />
                <h3 className="text-lg font-light uppercase mt-2">Websockets Proxy</h3>
                <input onChange={handleInputChange("proxy")} defaultValue={nodeManagerSettings.proxy} className={`w-full ${inputStyle({ accent: "blue" })}`} type="text" placeholder='Websocket Proxy' />
            </div>
            <button className="mt-4" onClick={handleSaveSettings}>Save Settings</button>
        </>
    )


}