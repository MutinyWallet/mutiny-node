
function Send() {
    return (
        <div className="flex flex-col h-screen">
            <header className='p-8 flex justify-start'>
                <h1 className="text-2xl uppercase border-b-2 pr-2 border-b-green">
                    Send
                </h1>
            </header>
            <main className='flex flex-grow flex-col h-full justify-between p-8'>
                <div />
                <div>
                    <input className='w-full' type="text" placeholder='Paste invoice' />
                </div>
                <div className='flex justify-start'>
                    <button>Continue</button>
                </div>
            </main>

        </div>

    );
}

export default Send;
