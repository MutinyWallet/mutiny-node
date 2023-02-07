import { useQuery } from "@tanstack/react-query";
import { satsToUsd } from "@util/conversions";
import prettyPrintAmount from "@util/prettyPrintAmount";
import { usePriceQuery } from "@util/queries";
import { MutinyBalance } from "@mutinywallet/node-manager";
import { useContext, useState } from "react";
import { NodeManagerContext } from "./GlobalStateProvider";

function prettyPrintBalance(b: MutinyBalance): string {
    return prettyPrintAmount(b.confirmed.valueOf() + b.lightning.valueOf())
}

function prettyPrintUnconfirmed(b: MutinyBalance): string {
    return prettyPrintAmount(b.unconfirmed.valueOf());
}

function prettyPrintUsdBalance(b: MutinyBalance, price: number): string {
    let sum = b.confirmed.valueOf() + b.lightning.valueOf()
    return prettyPrintUSD(Number(sum), price)
}

function prettyPrintUnconfirmedUsd(b: MutinyBalance, price: number): string {
    return prettyPrintUSD(Number(b.unconfirmed.valueOf()), price)
}

function prettyPrintUSD(amount: number, price: number): string {
    let usd = satsToUsd(amount, price);
    return prettyPrintAmount(Number(usd))
}

export default function MainBalance() {
    const { nodeManager } = useContext(NodeManagerContext);

    const [showFiat, setShowFiat] = useState(false)

    const { data: balance } = useQuery({
        queryKey: ['balance'],
        queryFn: () => {
            console.log("Checking balance...")
            return nodeManager?.get_balance()
        },
        enabled: !!nodeManager,
    })

    const { data: price } = usePriceQuery(nodeManager);

    return (<div className="flex flex-col gap-4 cursor-pointer" onClick={() => setShowFiat(!showFiat)}>
        {showFiat && price &&
            <h1 className='text-4xl font-light uppercase'>
                {balance && prettyPrintUsdBalance(balance, price)} <span className='text-2xl'>cuck bucks</span>
            </h1>
        }
        {(!showFiat || !price) &&
            <h1 className='text-4xl font-light uppercase'>
                {balance && prettyPrintBalance(balance)} <span className='text-2xl'>sats</span>
            </h1>
        }
        {(balance && balance.unconfirmed?.valueOf() > 0) && showFiat && price &&
            <div>
                <h1 className='text-4xl font-light uppercase opacity-70'>{balance && prettyPrintUnconfirmedUsd(balance, price)} <span className='text-2xl'>cuck bucks</span></h1>
                <small className='text-lg font-light uppercase opacity-70'>Unconfirmed</small>
            </div>
        }
        {(balance && balance.unconfirmed?.valueOf() > 0) && (!showFiat || !price) &&
            <div>
                <h1 className='text-4xl font-light uppercase opacity-70'>{balance && prettyPrintUnconfirmed(balance)} <span className='text-2xl'>sats</span></h1>
                <small className='text-lg font-light uppercase opacity-70'>Unconfirmed</small>
            </div>
        }
    </div>)
}
