import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useContext } from "react";
import { NodeManagerContext } from "./GlobalStateProvider";

export default function SyncOnInterval({ children }: { children: React.ReactNode }) {
    const { nodeManager } = useContext(NodeManagerContext);
    const queryClient = useQueryClient()

    async function handleSync() {
        console.time("BDK Sync Time")
        console.groupCollapsed("BDK Sync")
        try {
            await nodeManager?.sync()
        } catch (e) {
            console.error(e);
        }
        console.groupEnd();
        console.timeEnd("BDK Sync Time")
        await queryClient.invalidateQueries({ queryKey: ['balance'] })
        return true
    }

    // Do a sync every minute
    useQuery({
        queryKey: ['sync_every_minute'],
        queryFn: handleSync,
        enabled: !!nodeManager,
        refetchInterval: 1000 * 60,
        refetchOnWindowFocus: false
    })

    return <>{children}</>

}