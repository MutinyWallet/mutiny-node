// Stuff I'll probably delete when I do it "right"

import { NodeManager } from "node-manager";
import toast from "react-hot-toast";
export async function getFirstNode(nodeManager: NodeManager): Promise<string> {
    const myNodes = await nodeManager?.list_nodes();
    console.log(myNodes);
    const myNode = myNodes[0] as string

    if (!myNode) {
        throw new Error("We don't have a node set up yet!")
    }

    return myNode
}

export enum PaymentType {
    "invoice",
    "keysend",
    "onchain",
    "bip21",
    "unknown"
}

// TODO: use a real library for this or at least try harder
// https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
// https://en.bitcoin.it/wiki/List_of_address_prefixes
export function detectPaymentType(p: string): PaymentType {
    const lower = p.toLowerCase();
    if (lower.startsWith("lntb") || lower.startsWith("lnbcrt") || lower.startsWith("lnbc")) {
        return PaymentType.invoice
    } else if (lower.startsWith("03") || lower.startsWith("02")) {
        return PaymentType.keysend
    } else if (lower.startsWith("tb1") || lower.startsWith("bc1") || lower.startsWith("bcrt1") || lower.startsWith("1") || lower.startsWith("3") || lower.startsWith("2") || p.startsWith("m") || p.startsWith("n")) {
        return PaymentType.onchain
    } else if (lower.startsWith("bitcoin:")) {
        return PaymentType.bip21
    } else {
        return PaymentType.unknown
    }
}

export function toastAnything(e: unknown) {
    if (e instanceof Error) {
        toast(e.message)
    } else if (typeof e === "string") {
        toast(e as string)
    } else {
        toast(`Weird error! ${e}`)
    }
}

export function errorAsString(e: unknown): string {
    if (e instanceof Error) {
        return e.message
    } else if (typeof e === "string") {
        return e as string
    } else {
        return `Weird error! ${e}`
    }
}

export function mempoolTxUrl(txid?: string, network?: string) {
    if (!txid || !network) {
        console.error("Problem creating the mempool url")
        return "#"
    }

    return `https://mempool.space/${network === "testnet" ? "testnet" : ""}tx/${txid}`
}

export function objectToSearchParams<T extends Record<string, string | undefined>>(obj: T): string {
    return Object.entries(obj)
        .filter(([_, value]) => value !== undefined)
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value!)}`)
        .join("&");
}

export function getHostname(url: string): string {
    // Check if the URL begins with "ws://" or "wss://"
    if (url.startsWith("ws://")) {
        // If it does, remove "ws://" from the URL
        url = url.slice(5);
    } else if (url.startsWith("wss://")) {
        // If it begins with "wss://", remove "wss://" from the URL
        url = url.slice(6);
    }

    // Return the resulting URL
    return url;
}
