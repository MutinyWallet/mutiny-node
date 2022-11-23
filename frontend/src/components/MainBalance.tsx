import { useQuery } from "@tanstack/react-query";
import prettyPrintAmount from "@util/prettyPrintAmount";
import { MutinyBalance } from "node-manager";
import { useContext } from "react";
import { NodeManagerContext } from "./GlobalStateProvider";

function prettyPrintBalance(b: MutinyBalance): string {
    return prettyPrintAmount(b.confirmed.valueOf() + b.lightning.valueOf())
}

function prettyPrintUnconfirmed(b: MutinyBalance): string {
    return prettyPrintAmount(b.unconfirmed.valueOf());
}

export default function MainBalance() {
    const nodeManager = useContext(NodeManagerContext);

    const { data: balance } = useQuery({
        queryKey: ['balance'],
        queryFn: () => {
            console.log("Checking balance...")
            return nodeManager?.get_balance()
        },
        enabled: !!nodeManager,
    })
    return (<div className="flex flex-col gap-4 cursor-pointer">
        <h1 className='text-4xl font-light uppercase'>{balance && prettyPrintBalance(balance).toString()} <span className='text-2xl'>sats</span></h1>
        {(balance && balance.unconfirmed?.valueOf() > 0) &&
            <div>
                <h1 className='text-4xl font-light uppercase opacity-70'>{balance && prettyPrintUnconfirmed(balance).toString()} <span className='text-2xl'>sats</span></h1>
                <small className='text-lg font-light uppercase opacity-70'>Unconfirmed</small>
            </div>
        }
    </div>)
}