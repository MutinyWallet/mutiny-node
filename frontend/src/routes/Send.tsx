import { useNavigate } from "react-router";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
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
      <ScreenMain>
        <div />
        <div>
          <input className={`w-full ${inputStyle({ accent: "green" })}`} type="text" placeholder='Paste invoice' />
        </div>
        <div className='flex justify-start'>
          <button onClick={handleContinue}>Continue</button>
        </div>
      </ScreenMain>
    </div>
  );
}

export default Send;
