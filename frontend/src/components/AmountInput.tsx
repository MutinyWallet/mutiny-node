import { useQuery } from "@tanstack/react-query";
import prettyPrintAmount from "@util/prettyPrintAmount";
import { Dispatch, SetStateAction, useContext, useState } from "react";
import { inputStyle, selectStyle } from "../styles";
import { NodeManagerContext } from "./GlobalStateProvider";

type Props = {
    amountSats: string,
    setAmount: Dispatch<SetStateAction<string>>,
    accent: "green" | "blue" | "red",
    placeholder: string,
}

export enum Currency {
    USD = "USD",
    SATS = "SATS"
}

function satsToUsd(amount: number, price: number): string {
    let btc = amount / 100000000;
    let usd = btc * price;
    return usd.toFixed(2);
}

function usdToSats(amount: number, price: number): string {
    let btc = amount / price;
    let sats = btc * 100000000;
    return sats.toFixed(0);
}

export default function AmountInput({ amountSats, setAmount, accent, placeholder }: Props) {
    const [currency, setCurrency] = useState(Currency.SATS)

    // amountSats will be our source of truth, this is just for showing to the user
    const [localDisplayAmount, setLocalDisplayAmount] = useState(amountSats)

    const { nodeManager } = useContext(NodeManagerContext);

    const { data: price } = useQuery({
        queryKey: ['price'],
        queryFn: async () => {
            console.log("Checking bitcoin price...")
            return await nodeManager?.get_bitcoin_price()
        },
        enabled: !!nodeManager,
    })

    function setAmountFormatted(value: string) {
        if (value.length === 0 || value === "0") {
            setAmount('')
            setLocalDisplayAmount('')
            return
        }
        //Use a regex to replace all commas and underscores with empty string
        const amount = value.replace(/[_,]/g, "");
        let parsedAmount = parseInt(amount)
        if (typeof parsedAmount === "number" && parsedAmount !== 0 && price) {
            // If the currency is set to usd, we need to convert the input amount to sats and store that in setAmount
            if (currency === Currency.USD) {
                setAmount(usdToSats(parsedAmount, price))
                // Then we set the usd amount to localDisplayAmount
                setLocalDisplayAmount(prettyPrintAmount(parsedAmount))
            } else {
                // Otherwise we can just set the amount to the parsed amount
                setAmount(prettyPrintAmount(parsedAmount))
                // And the localDisplayAmount to the same thing
                setLocalDisplayAmount(prettyPrintAmount(parsedAmount))
            }
        } else {
            setAmount('')
            setLocalDisplayAmount('')
        }
    }

    function handleCurrencyChange(value: Currency) {
        setCurrency(value)
        const amount = amountSats.replace(/[_,]/g, "");
        let parsedAmount = parseInt(amount)
        if (typeof parsedAmount === "number" && price) {
            if (value === Currency.USD) {
                // Then we set the usd amount to localDisplayAmount
                let dollars = satsToUsd(parsedAmount, price)
                let parsedDollars = Number(dollars);
                if (parsedDollars === 0) {
                    // 0 looks lame
                    setLocalDisplayAmount("");
                } else {
                    setLocalDisplayAmount(prettyPrintAmount(parsedDollars))
                }
            } else if (value === Currency.SATS) {
                // And the localDisplayAmount to the same thing
                setLocalDisplayAmount(prettyPrintAmount(parsedAmount))
            }
        }
    }

    return (
        <>
            {/* HANDY DEBUGGER FOR UNDERSTANDING */}
            {/* <pre>{JSON.stringify({ currency, amountSats, localDisplayAmount }, null, 2)}</pre> */}
            <div className="flex gap-2">
                <input onChange={e => setAmountFormatted(e.target.value)} value={localDisplayAmount} className={inputStyle({ accent, width: "wide" })} type="text" inputMode={currency === Currency.SATS ? "numeric" : "decimal"} placeholder={placeholder} />
                <div className="select-wrapper bg-red">
                    <select id="currency" value={currency} onChange={e => handleCurrencyChange(e.target.value as Currency)} className={selectStyle({ accent })}>
                        <option value={Currency.SATS}>SATS</option>
                        <option value={Currency.USD}>USD</option>
                    </select>
                </div>
            </div>
        </>
    )

}