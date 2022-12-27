
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

const selectStyle = cva("", {
    variants: {
        accent: {
            green: "bg-green focus:ring-green",
            blue: "bg-blue focus:ring-blue",
            red: "bg-red focus:ring-red",
        },
    }
});

const mainWrapperStyle = cva("flex flex-col justify-between overflow-y-scroll mb-4 gap-4", {
    variants: {
        // TODO: this is kind of hacky but flexbox is a struggle
        scrolls: {
            no: "h-full",
            yes: "h-auto"
        },
        padSides: {
            yes: "p-8",
            no: "py-8"
        }
    },
    defaultVariants: {
        scrolls: "no",
        padSides: "yes"
    }

});

export { inputStyle, selectStyle, mainWrapperStyle }
