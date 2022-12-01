import MutinyToaster from "@components/MutinyToaster";
import { useNavigate } from "react-router-dom";
import Close from "../components/Close";
import PageTitle from "../components/PageTitle";
import ScreenMain from "../components/ScreenMain";
import Bear from "@images/48/bear.gif"
import Bull from "@images/48/bull.gif"
import prettyPrintAmount from "@util/prettyPrintAmount";
import prettyPrintTime from "@util/prettyPrintTime";
import takeN from "@util/takeN";

export const DLC_ACCOUNCEMENT_HEX = "fdd824fd02d339dd8c386d9e13b7afd8939a9cf090586fb5928d3225ac875a3f7c5028480415c2c7cfb262ea87dc257de2765bbcf8fa41ad4ade1ffd57d4d7f66f827fb3dae904ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8defdd822fd026d00122f1b7d78a83789807dadb418c847bf34ca30df12478aa2471867b0ef4d09471a0ade270183fcc3aad3b548e0f9ba86efe5e276d400448a6dd70f47bae4ccc09f7bab63ac9bf5a5cc6eb79e09b89439ef3969f9a6911060075015586844e42c0c30507fadbe3f02eb7b0aee3990eb89905e739924ed483c66f947a0f8f1cba89b2489034d4ece69fb10469045b09046cb465b5dd34035a61e2771f3eaab0653661fc03868f28ecc016fac3e60cd51ef87dcb76c8388a8dc08adeafaea9da562a99401e738fbcec2e3b78046dbd889230ef3a295f9a4dda9bc35afa31dde6bfddda5a852ff6f0a5f358ceee407d8c4ca5421c5e87026e7b704300c34e8b9315f666a803d32b73d81cedb01893a1510a832d82c6d9a7d47a6c3e6135a8e164c6e764033508a14cecec76842f8495ca111357e79fe53ccd20fc01d6b7b9e951acedfc30bd06955a39f10577a6b6f1b5dfb210879846834caf6f57f07d770334ffc2e80773befe79d4ab870deefe1d4df3784908e06413a84b8b9db4cdf3189a5c6e56dcee723b832985e8a717f7f6f4fe76925b0915172ffe9bd1c91052224420532759d5a787bdad172841aacc4268ca9e42c164d5d1ae861505fa7f96f7975f32a6c3ee1bc88d7a09c29694bcb4b6efbdd1149b05bf8f3d78c7b2432dd4de7111e7fad76afe59ef0fc5ba65e64047ca8fe24cf5ed867ce301433e5754a94552cbd544f8affa7817f8f43662378a52e24ed830b09d6e1ad4ecfed8ce5f01cc0d122f31ebc3a6d8e413c1702ce0ecc821cf6a2db8ceec1b4b4e9687af58fb7c09148610b9a80fdd80a100002000642544355534400000000001212446572696269742d4254432d354155473231"

export default function FinalJoinDLC() {
	const navigate = useNavigate();

	function handleNavDLCs() {
		navigate("/manager/dlcs")
	}

	let bullish = true;

	return (
		<>
			<header className='p-8 flex justify-between items-center'>
				<PageTitle title="Create a DLC" theme="green"></PageTitle>
				<Close route="/manager/dlcs" />
			</header>
			<ScreenMain>
				<div />
				<p className="text-2xl font-light">You're in! Good luck and have fun.</p>
				<div className="w-full flex items-center gap-2">
					<div className="w-16 h-16 flex items-center justify-center">
						<img src={bullish ? Bull : Bear} alt="bullish" />
					</div>
					<div>
						<h3 className="text-lg font-mono">
							{takeN(DLC_ACCOUNCEMENT_HEX, 25)}
						</h3>
						<h3 className="text-lg font-light">
							{prettyPrintAmount(10000)} sats
						</h3>
						<a href="https://oracle.suredbits.com/announcement/b9dc30042a93daf9d9f3ab9486d7323942b03289b08c946dc14a5522f49242c6" target="_blank" rel="noreferrer">Details</a>
						<h4 className="text-sm font-light opacity-50">Expires {prettyPrintTime(420420)}</h4>
					</div>
				</div>

				<div className='flex justify-start'>
					<button onClick={handleNavDLCs}>Nice</button>
				</div>
				<MutinyToaster />
			</ScreenMain>
		</>
	)
}
