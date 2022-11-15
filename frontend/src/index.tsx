import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import App from './routes/App';
import * as serviceWorkerRegistration from './serviceWorkerRegistration';
import reportWebVitals from './reportWebVitals';
import {
  createBrowserRouter,
  RouterProvider,
} from "react-router-dom";
import KitchenSink from './routes/KitchenSink';
import Send from './routes/Send';
import Deposit from './routes/Deposit';
import SendConfirm from './routes/SendConfirm';
import Receive from './routes/Receive';
import ManagerRoot from './routes/ManagerRoot';
import Transactions from './routes/Transactions';
import Peers from './routes/Peers';
import Channels from './routes/Channels';
import Settings from './routes/Settings';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

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
        path: "peers",
        element: <Peers />
      },
      {
        path: "channels",
        element: <Channels />
      },
      {
        path: "settings",
        element: <Settings />
      }
    ]
  }
]);

root.render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>
);

// Learn more about service workers: https://cra.link/PWA
serviceWorkerRegistration.register();

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
