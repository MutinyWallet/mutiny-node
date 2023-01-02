import { defineConfig, searchForWorkspaceRoot } from 'vite';
import react from '@vitejs/plugin-react';
import viteTsconfigPaths from 'vite-tsconfig-paths';
import svgrPlugin from 'vite-plugin-svgr';
import wasm from "vite-plugin-wasm";

// https://vitejs.dev/config/
export default defineConfig({
    plugins: [wasm(), react(), viteTsconfigPaths(), svgrPlugin()],
    build: {
        outDir: "build"
    },
    server: {
        port: 3000,
        fs: {
            allow: [
                searchForWorkspaceRoot(process.cwd()),
                "../node-manager/pkg"]
        }
    }
});
