import React, { createContext, Dispatch, useState } from "react"

const INITIAL_STATE = "transactions"

export const ManagerRouteContext = createContext<{
    managerRoute: string;
    setManagerRoute: Dispatch<string>;
}>({
    managerRoute: INITIAL_STATE,
    setManagerRoute: () => { }
});

export default function ManagerRouteProvider({ children }: { children: React.ReactNode }) {
    const [managerRoute, setManagerRoute] = useState(INITIAL_STATE);

    return (
        <ManagerRouteContext.Provider value={{ managerRoute, setManagerRoute }}>
            {children}
        </ManagerRouteContext.Provider>
    );
};