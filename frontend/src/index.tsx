import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';

import Router from '@components/Router';
import { GlobalStateProvider } from '@components/GlobalStateProvider';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ManagerRouteProvider from '@components/ManagerRouteProvider';
import SyncOnInterval from '@components/SyncOnInterval';

const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

const queryClient = new QueryClient()

root.render(
  <React.StrictMode>
    <GlobalStateProvider>
      <QueryClientProvider client={queryClient}>
        <SyncOnInterval>
          <ManagerRouteProvider>
            <Router />
          </ManagerRouteProvider>
        </SyncOnInterval>
      </QueryClientProvider>
    </GlobalStateProvider>
  </React.StrictMode>
);