interface ImportMetaEnv {
    readonly VITE_APP_NETWORK: string;
    readonly VITE_APP_PROXY: string;
    readonly VITE_APP_ESPLORA: string;
    readonly VITE_APP_COMMIT_HASH: string;
}

interface ImportMeta {
    readonly env: ImportMetaEnv;
}