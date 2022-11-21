
import logo from '../images/mutiny-logo.svg';
import { useNavigate } from "react-router-dom";
import { useEffect, useState } from 'react';
import ScreenMain from '../components/ScreenMain';
import More from '../components/More';
import MutinyToaster from '../components/MutinyToaster';
import { useContext } from 'react';
import { NodeManagerContext } from '@components/GlobalStateProvider';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { MutinyBalance } from 'node-manager';
import prettyPrintAmount from '@util/prettyPrintAmount';

function prettyPrintBalance(b: MutinyBalance): string {
  return prettyPrintAmount(b.confirmed.valueOf() + b.lightning.valueOf())
}

function App() {
  const nodeManager = useContext(NodeManagerContext);

  const queryClient = useQueryClient()

  const { error, data: balance } = useQuery({
    queryKey: ['balance'],
    queryFn: () => {
      console.log("checking balance...")
      return nodeManager?.get_balance()
    },
    enabled: !!nodeManager,
  })

  let navigate = useNavigate();

  function handleNavSend() {
    navigate("/send")
  }

  function handleNavReceive() {
    navigate("/receive")
  }

  async function handleCheckBalance() {
    queryClient.invalidateQueries({ queryKey: ['balance'] })
  }

  async function handleSync() {
    await nodeManager?.sync()
    queryClient.invalidateQueries({ queryKey: ['balance'] })
  }

  return (
    <>
      <header className='p-8'>
        <img src={logo} className="App-logo" alt="logo" />
        <h2>You're probably looking for <a href="/tests">the tests</a></h2>

      </header>
      <ScreenMain>
        {nodeManager ?
          <>
            <div />
            {error && error instanceof Error && <h1>{error.message}</h1>}
            <h1 className='text-4xl font-light uppercase'>{balance && prettyPrintBalance(balance).toString()} <span className='text-2xl'>sats</span></h1>
            <div />
            <div className='flex flex-col gap-2 items-start'>
              <button onClick={handleSync}>Sync</button>
              <button onClick={handleCheckBalance}>Check balance</button>
              <button className='green-button' onClick={handleNavSend}>Send</button>
              {/* TODO if no funds can do deposit instead of receive */}
              {/* <button className='blue-button' onClick={handleNavDeposit}>Deposit</button> */}
              <div className='w-full flex justify-between items-center'>
                <button className='blue-button' onClick={handleNavReceive}>Receive</button>
                <More />
              </div>
            </div>
          </>
          : <h1>Loading...</h1>}
        <MutinyToaster />
      </ScreenMain>
    </>
  );
}

export default App;
