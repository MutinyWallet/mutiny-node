import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import * as serviceWorkerRegistration from './serviceWorkerRegistration';
import reportWebVitals from './reportWebVitals';

import Router from '@components/Router';
import { GlobalStateProvider } from '@components/GlobalStateProvider';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ManagerRouteProvider from '@components/ManagerRouteProvider';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

const queryClient = new QueryClient()

root.render(
  <React.StrictMode>
    <GlobalStateProvider>
      <QueryClientProvider client={queryClient}>
        <ManagerRouteProvider>
          <Router />
        </ManagerRouteProvider>
      </QueryClientProvider>
    </GlobalStateProvider>
  </React.StrictMode>
);

// Learn more about service workers: https://cra.link/PWA
serviceWorkerRegistration.register();

// If you want to start measuring performance in your app, pass a function
// to log results (for example: reportWebVitals(console.log))
// or send to an analytics endpoint. Learn more: https://bit.ly/CRA-vitals
reportWebVitals();
