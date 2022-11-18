
import { cva } from "class-variance-authority";

const inputStyle = cva("", {
    variants: {
        accent: {
            green: "border-green focus:ring-green",
            blue: "border-blue focus:ring-blue",
            red: "border-red focus:ring-red",
        },
        width: {
            normal: "",
            wide: "w-full"
        }
    },
    defaultVariants: {
        width: "normal"
    }
});

export { inputStyle }