import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import { useSearchParams } from "react-router-dom";
import ActionButton from "@components/ActionButton";

export default function SendFinal() {
  let navigate = useNavigate();

  const [searchParams] = useSearchParams();
  const txid = searchParams.get("txid")

  function handleNice() {
    navigate("/")
  }

  return (
    <>
      <header className='p-8 flex justify-between items-center'>
        <PageTitle title="Confirm" theme="green" />
        <Close />
      </header>
      <ScreenMain>
        <div />
        <p className="text-2xl font-light">Sent!</p>
        {!!txid &&
          <dl>
            <div className="rounded border p-2 my-2 font-mono break-words">
              <dt>TXID</dt>
              <dd>
                {txid}
              </dd>
            </div>
          </dl>
        }
        <ActionButton onClick={handleNice}>Nice</ActionButton>
      </ScreenMain>
    </>
  );
}
