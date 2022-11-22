// Stuff I'll probably delete when I do it "right"

import { NodeManager } from "node-manager";
export async function getFirstNode(nodeManager: NodeManager): Promise<string> {
    const myNodes = await nodeManager?.list_nodes();
    console.log(myNodes);
    const myNode = myNodes[0] as string

    if (!myNode) {
        throw new Error("We don't have a node set up yet!")
    }

    return myNode
}