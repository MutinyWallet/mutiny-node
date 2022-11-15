import { useState } from "react";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";

function SendConfirm() {

  const [sent, setSent] = useState(false)

  function handleSend() {
    setSent(true);
  }

  let navigate = useNavigate();

  function handleNice() {
    navigate("/")
  }

  return (
    <div className="flex flex-col h-screen">
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Confirm" theme="green" />
        <Close />
      </header>
      {sent &&
        <ScreenMain>
          <div />
          <p className="text-2xl font-light">Sent!</p>
          <div className='flex justify-start'>
            <button onClick={handleNice}>Nice</button>
          </div>
        </ScreenMain>
      }
      {!sent &&
        <ScreenMain>
          <div />
          <p className="text-2xl font-light">How does this look to you?</p>
          <dl>
            <h4 className="bg-gray-button shadow-button">Info</h4>
            <div className="bg-faint rounded p-2 my-2">
              <dt>Who</dt>
              <dd>satoshis.place</dd>
            </div>
            <div className="bg-faint rounded p-2 my-2">
              <dt>How Much</dt>
              <dd>42 sat</dd>
            </div>
            <div className="bg-faint rounded p-2 my-2 flex flex-col">
              <dt>What For</dt>
              <dd>Payment for 42 pixels at satoshis.place</dd>
              <a href="/" className="self-end mt-4">Edit</a>
            </div>
          </dl>
          <div className='flex justify-start'>
            <button onClick={handleSend}>Send</button>
          </div>
        </ScreenMain>
      }
    </div>

  );
}

export default SendConfirm;
