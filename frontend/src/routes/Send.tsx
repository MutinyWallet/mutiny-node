import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import { inputStyle } from "../styles";

function Send() {
  let navigate = useNavigate();
  function handleContinue() {
    navigate("/send/confirm")

  }
  return (
    <div className="flex flex-col h-screen">
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Send" theme="green" />
        <Close />
      </header>
      <main className='flex flex-grow flex-col h-full justify-between p-8 mb-4'>
        <div />
        <div>
          <input className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice' />
        </div>
        <div className='flex justify-start'>
          <button onClick={handleContinue}>Continue</button>
        </div>
      </main>
    </div>
  );
}

export default Send;
