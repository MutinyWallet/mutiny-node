export default function ActionButton({ children, onClick }: React.ComponentPropsWithoutRef<"button">) {
    return <div className='flex justify-start'>
        <button onClick={onClick}>{children}</button>
    </div>
}