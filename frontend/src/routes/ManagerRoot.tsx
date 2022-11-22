import { Outlet, useLocation, useNavigate } from "react-router-dom";
import TxIcon from "../images/tx-icon.png"
import ChannelsIcon from "../images/channels-icon.png"
import SettingsIcon from "../images/settings-icon.png"
import OnChainIcon from "../images/world-in-box-icon.png"
import PeersIcon from "../images/peers-icon.png"
import UtxosIcon from "@images/utxos-icon.png"

function ManagerRoot() {
    let navigate = useNavigate();
    let location = useLocation();

    const shouldBeActive = (matcher: string) => {
        return location.pathname === `/manager/${matcher}` ? "" : "secondary"
    }

    return (
        <div className="flex flex-col h-full fixed w-full">
            <Outlet />
            <nav className="relative">
                <ul className="pb-8 pt-16 px-8 flex overflow-x-scroll gap-2 absolute bottom-0 left-0 right-0 max-w-full bg-fade-to-blue scrollbar-hide">
                    <li>
                        <button onClick={() => navigate("transactions")} className={shouldBeActive("transactions")} >
                            <img src={TxIcon} alt="transactions icon" />
                            TXs
                        </button>
                    </li>
                    <li>
                        <button onClick={() => navigate("channels")} className={shouldBeActive("channels")}>
                            <img src={ChannelsIcon} alt="chanels icon" />
                            Channels
                        </button>
                    </li>
                    <li>
                        <button onClick={() => navigate("onchain")} className={shouldBeActive("onchain")}>
                            <img src={OnChainIcon} alt="onchain icon" />
                            On-chain
                        </button>
                    </li>
                    <li>
                        <button onClick={() => navigate("peers")} className={shouldBeActive("peers")}>
                            <img src={PeersIcon} alt="peers icon" />
                            Peers
                        </button>
                    </li>
                    <li>
                        <button onClick={() => navigate("utxos")} className={shouldBeActive("utxos")}>
                            <img src={UtxosIcon} alt="utxos icon" />
                            Utxos
                        </button>
                    </li>
                    <li>
                        <button onClick={() => navigate("settings")} className={shouldBeActive("settings")}>
                            <img src={SettingsIcon} alt="settings icon" />
                            Settings
                        </button>
                    </li>
                </ul>
            </nav>
        </div>
    )
}

export default ManagerRoot