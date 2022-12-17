import {
    createBrowserRouter,
    RouterProvider,
} from "react-router-dom";
import KitchenSink from '@routes/KitchenSink';
import App from '@routes/App';
import Send from '@routes/Send';
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
import ReceiveQR from "@routes/ReceiveQR";
import SendFinal from "@routes/SendFinal";
import NotFound from "@routes/NotFound";

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
        path: "/send/final",
        element: <SendFinal />,
    },
    {
        path: "/receive",
        element: <Receive />,
    },
    {
        path: "/receive/qr",
        element: <ReceiveQR />,
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
    },
    {
        path: "*",
        element: <NotFound />
    }
]);

export default function Router() {
    return <RouterProvider router={router} />
}