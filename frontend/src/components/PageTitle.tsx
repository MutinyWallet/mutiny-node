
import { cva } from "class-variance-authority";

const titleStyle = cva("text-2xl uppercase border-b-2 pr-2", {
    variants: {
        accent: {
            green: "border-b-green",
            blue: "border-b-blue",
            red: "border-b-red",
            white: "border-b-off-white",
        },
    },
});

export default function PageTitle({ title, theme }: { title: string, theme: "green" | "blue" | "red" | "white" }) {
    return (<h1 className={titleStyle({ accent: theme })}>
        {title}
    </h1>);
}