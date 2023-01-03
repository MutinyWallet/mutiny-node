import { GlobalStateProvider } from '@components/GlobalStateProvider';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import Router from '@components/Router';

import App from './App';

const queryClient = new QueryClient()

describe('App', () => {
    it('renders app', () => {
        render(
            <GlobalStateProvider>
                <QueryClientProvider client={queryClient}>
                    <Router />
                </QueryClientProvider>
            </GlobalStateProvider>
        )

        screen.debug();

        // check if App components renders headline
    });
});