import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import QRCode from "react-qr-code"
import Copy from "../components/Copy";
import { useNavigate } from "react-router";

const TEST_ADDRESS = "tb1p5stsdxw7rhqfm72ylduqds7pvud3qcuuqh8wjej88v5mx22jnu6qymt83p"

function Deposit() {
  let navigate = useNavigate();
  function handleCancel() {
    navigate("/")

  }
  return (
    <div className="flex flex-col h-screen">
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Deposit" theme="blue"></PageTitle>
        <Close />
      </header>
      <ScreenMain>
        <div />
        <p className="text-2xl font-light">Add on-chain funds</p>
        <div className="flex flex-col items-start gap-4">
          <div className="bg-[#ffffff] p-4">
            <QRCode value={TEST_ADDRESS} />
          </div>
          <div className="bg-faint rounded p-2 my-2 flex gap-2 items-center">
            <div className="flex-1">
              <p className="text-lg font-mono font-light break-all">{TEST_ADDRESS}</p>
            </div>
            <Copy copyValue={TEST_ADDRESS} />
          </div>
        </div>

        <div className='flex justify-start'>
          <button onClick={handleCancel}>Cancel</button>
        </div>
      </ScreenMain>
    </div>
  );
}

export default Deposit;
