import { NodeManager } from "node-manager";

export function satsToUsd(amount: number, price: number): string {
    if (typeof amount !== "number" || isNaN(amount)) {
        return ""
    }
    try {
        let btc = NodeManager.convert_sats_to_btc(BigInt(Math.floor(amount)));
        let usd = btc * price;
        return usd.toFixed(2);
    } catch (e) {
        console.error(e);
        return ""
    }
}

export function usdToSats(amount: number, price: number): string {
    if (typeof amount !== "number" || isNaN(amount)) {
        return ""
    }
    try {
        let btc = amount / price;
        let sats = NodeManager.convert_btc_to_sats(btc);
        return sats.toString();
    } catch (e) {
        console.error(e);
        return ""
    }
}