/// <reference types="vitest" />
import { defineConfig, searchForWorkspaceRoot } from 'vite';
import react from '@vitejs/plugin-react';
import viteTsconfigPaths from 'vite-tsconfig-paths';
import svgrPlugin from 'vite-plugin-svgr';
import wasm from "vite-plugin-wasm";

// https://vitejs.dev/config/
export default defineConfig({
    optimizeDeps: {
        disabled: false,
        // include: ["node-manager"]
    },
    plugins: [wasm(), react(), viteTsconfigPaths(), svgrPlugin()],
    build: {
        outDir: "build",
        commonjsOptions: {
            include: [/node-manager/]
        }
    },
    server: {
        port: 3000,
        fs: {
            allow: [
                searchForWorkspaceRoot(process.cwd()),
                "../node-manager/pkg"]
        }
    },
    test: {
        globals: true,
        environment: 'jsdom',
        setupFiles: './src/setupTests.ts',
        coverage: {
            reporter: ['text', 'html'],
            exclude: [
                'node_modules',
                'src/setupTests.ts',
            ],
        },
    },
});
