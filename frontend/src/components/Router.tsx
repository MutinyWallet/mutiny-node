import {
    createBrowserRouter,
    RouterProvider,
} from "react-router-dom";
import KitchenSink from '@routes/KitchenSink';
import App from '@routes/App';
import Send from '@routes/Send';
import Deposit from '@routes/Deposit';
import SendConfirm from '@routes/SendConfirm';
import Receive from '@routes/Receive';
import ManagerRoot from '@routes/ManagerRoot';
import Transactions from '@routes/Transactions';
import Peers from '@routes/Peers';
import Channels from '@routes/Channels';
import Settings from '@routes/Settings';
import OnChain from '@routes/OnChain';
import OpenChannel from '@routes/OpenChannel';
import Utxos from "@routes/Utxos";
import ConnectPeer from "@routes/ConnectPeer";
import SendAmount from "@routes/SendAmount";
import ReceiveFinal from "@routes/ReceiveFinal";
import DLCs from "@routes/DLCs";
import NewDLC from "@routes/NewDLC";
import ConfirmNewDLC from "@routes/ConfirmNewDLC";
import FinalNewDLC from "@routes/FinalNewDLC";
import JoinDLC from "@routes/JoinDLC";
import ConfirmJoinDLC from "@routes/ConfirmJoinDLC";
import FinalJoinDLC from "@routes/FinalJoinDLC";

const router = createBrowserRouter([
    {
        path: "/",
        element: <App />,
    },
    {
        path: "/send",
        element: <Send />,
    },
    {
        path: "/send/amount",
        element: <SendAmount />,
    },
    {
        path: "/send/confirm",
        element: <SendConfirm />,
    },
    {
        path: "/deposit",
        element: <Deposit />,
    },
    {
        path: "/receive",
        element: <Receive />,
    },
    {
        path: "/receive/final",
        element: <ReceiveFinal />,
    },
    {
        path: "/openchannel",
        element: <OpenChannel />,
    },
    {
        path: "/connectpeer",
        element: <ConnectPeer />,
    },
    {
        path: "/new-dlc",
        element: <NewDLC />,
    },
    {
        path: "/new-dlc/confirm",
        element: <ConfirmNewDLC />,
    },
    {
        path: "/new-dlc/final",
        element: <FinalNewDLC />,
    },
    {
        path: "/join-dlc",
        element: <JoinDLC />,
    },
    {
        path: "/join-dlc/confirm",
        element: <ConfirmJoinDLC />,
    },
    {
        path: "/join-dlc/final",
        element: <FinalJoinDLC />,
    },
    {
        path: "/tests",
        element: <KitchenSink />,
    },
    {
        path: "/manager",
        element: <ManagerRoot />,
        children: [
            {
                path: "transactions",
                element: <Transactions />
            },
            {
                path: "onchain",
                element: <OnChain />
            },
            {
                path: "dlcs",
                element: <DLCs />
            },
            {
                path: "peers",
                element: <Peers />
            },
            {
                path: "channels",
                element: <Channels />
            },
            {
                path: "utxos",
                element: <Utxos />
            },
            {
                path: "settings",
                element: <Settings />
            }
        ]
    }
]);

export default function Router() {
    return <RouterProvider router={router} />
}