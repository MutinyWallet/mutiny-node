import React, { createContext, Dispatch, useEffect, useState } from "react"
import { ReactComponent as Prompt } from "@images/prompt.svg"
import { ReactComponent as CloseIcon } from "@images/icons/close.svg"

export const TerminalProviderContext = createContext<{
    showTerminal: boolean;
    setShowTerminal: Dispatch<boolean>;
}>({
    showTerminal: true,
    setShowTerminal: () => { }
});

function compareLogs(a: string, b: string) {
    // Get the timestamp of the first log
    const timestampA = a.substring(0, 19);
    // Get the timestamp of the second log
    const timestampB = b.substring(0, 19);

    // Compare the timestamps and return the result
    if (timestampA < timestampB) {
        return -1;
    }
    if (timestampA > timestampB) {
        return 1;
    }
    return 0;
}

function getAllLogs() {
    let logs: string[] = [];

    // Loop over all keys in local storage that start with "log_"
    for (let i = 0; i < localStorage.length; i++) {
        let key = localStorage.key(i);
        if (key?.startsWith("log_")) {
            // Get the log from local storage and add it to the array of logs
            let log = localStorage.getItem(key) || "";
            logs.push(JSON.parse(log));
        }
    }

    return logs.sort(compareLogs).reverse();
}

// function getAllLogsNewerThan(timestamp: number): string[] {
//     let logs: string[] = [];

//     // Loop over all keys in local storage that start with "log_"
//     for (let i = 0; i < localStorage.length; i++) {
//         let key = localStorage.key(i);
//         if (key?.startsWith("log_")) {
//             // Extract the timestamp from the log key
//             let timestamp_string = key.replace("log_", "");
//             let log_timestamp = parseInt(timestamp_string);

//             // Check if the log's timestamp is greater than the given timestamp
//             if (log_timestamp > timestamp) {
//                 // Get the log from local storage and add it to the array of logs
//                 let log = localStorage.getItem(key) || "";
//                 logs.push(log);
//             }
//         }
//     }

//     return logs;
// }

function clearLogs() {
    // Get all keys in localStorage
    const keys = Object.keys(localStorage);

    // Loop through each key and check if it has a prefix of "log_"
    keys.forEach((key) => {
        if (key.startsWith('log_')) {
            // If the key has a prefix of "log_", remove the corresponding entry from localStorage
            localStorage.removeItem(key);
        }
    });
}

function Logs() {
    const [logs, setLogs] = useState<string[]>([]);

    useEffect(() => {
        setLogs(getAllLogs());

        // Define the polling function
        function pollForChanges() {
            // Check if the logs in local storage have changed since the last poll
            const updatedLogs = getAllLogs();
            if (updatedLogs !== logs) {
                // Update the component's state with the updated logs
                setLogs(updatedLogs);
            }
        }
        // Register an event listener that will be executed whenever the `storage` event is fired
        const interval = setInterval(pollForChanges, 1000);

        // Return a cleanup function that will be executed when the component is unmounted
        return () => {
            // Clear the interval when the component is unmounted
            clearInterval(interval);
        };
    }, []);

    return (
        <ul className="h-full overflow-y-scroll">
            {logs.map((log, index) => (
                <li key={index}>{log}</li>
            ))}
        </ul>
    );
}

function Terminal() {
    const [open, setOpen] = useState(false)
    return (
        <>
            {open ?
                <div className="fixed left-0 top-0 w-screen h-screen bg-faint-black p-4 font-mono">
                    <div className="flex w-full justify-between">
                        <button onClick={clearLogs}>Clear</button>
                        <div onClick={() => setOpen(false)} className="h-10 w-10 min-w-10 text-white active:text-half-faint" >
                            <CloseIcon />
                        </div>
                    </div>
                    <Logs />
                </div >
                :
                <footer onClick={() => setOpen(true)} className="bg-black p-4 flex gap-2 items-center font-mono relative">
                    <div><Prompt /></div>
                    <p>I'm a terminal!</p>
                </footer>
            }
        </>
    )
}

export default function TerminalProvider({ children }: { children: React.ReactNode }) {
    const [showTerminal, setShowTerminal] = useState(true);

    return (
        <TerminalProviderContext.Provider value={{ showTerminal, setShowTerminal }}>
            {children}
            {showTerminal && <Terminal />}
        </TerminalProviderContext.Provider>
    );
};