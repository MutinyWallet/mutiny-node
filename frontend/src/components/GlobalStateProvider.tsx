import init, { InitOutput, NodeManager } from 'node-manager';
import React, { createContext, useEffect, useState } from 'react';

interface Props {
    children: React.ReactElement;
}

export const NodeManagerContext = createContext<NodeManager | undefined>(undefined);

const MNEMONIC = "oak cart nasty cube noise icon pumpkin salmon photo fury asset file"

export const GlobalStateProvider = ({ children }: Props) => {
    // eslint-disable-next-line
    const [_wasm, setWasm] = useState<InitOutput>();
    const [nodeManager, setNodeManager] = useState<NodeManager>();

    useEffect(() => {
        // TODO: learn why we init this but don't actually call stuff on it
        init().then((wasmModule) => {
            setWasm(wasmModule)
            setup().then(() => {
                console.log("Setup complete")
            }).catch((e) => {
                console.error(e)
            })
        })
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    async function setup() {
        console.log("Starting setup...")
        try {
            console.log("Initializing Node Manager")
            let nodeManager = await new NodeManager("", MNEMONIC)
            // TODO this is some extra delay because the node manager isn't really "ready" the moment it's set
            await timeout(100)
            setNodeManager(nodeManager)
        } catch (e) {
            console.error(e)
        }
    }

    return (
        <NodeManagerContext.Provider value={nodeManager}>
            {children}
        </NodeManagerContext.Provider>
    )
}

function timeout(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}