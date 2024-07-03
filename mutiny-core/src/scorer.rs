use crate::{logging::MutinyLogger, node::NetworkGraph};
use lightning::routing::router::CandidateRouteHop;
use lightning::{
    routing::{
        gossip::NodeId,
        router::Path,
        scoring::{
            ChannelUsage, ProbabilisticScorer, ProbabilisticScoringFeeParameters, ScoreLookUp,
            ScoreUpdate,
        },
    },
    util::ser::{Writeable, Writer},
};
use std::time::Duration;
use std::{collections::HashSet, str::FromStr, sync::Arc};

const HUB_BASE_DISCOUNT_PENALTY_MSAT: u64 = 100_000;

const PUBKEYS: [&str; 251] = [
    "03aefa43fbb4009b21a4129d05953974b7dbabbbfb511921410080860fca8ee1f0", // Voltage Flow 2.0
    "035e4ff418fc8b5554c5d9eea66396c227bd429a3251c8cbc711002ba215bfc226",
    "02f1a8c87607f415c8f22c00593002775941dea48869ce23096af27b0cfdcc0b69",
    "024bfaf0cabe7f874fd33ebf7c6f4e5385971fc504ef3f492432e9e3ec77e1b5cf",
    "033878501f9a4ce97dba9a6bba4e540eca46cb129a322eb98ea1749ed18ab67735",
    "03423790614f023e3c0cdaa654a3578e919947e4c3a14bf5044e7c787ebd11af1a",
    "02e4971e61a3f55718ae31e2eed19aaf2e32caf3eb5ef5ff03e01aa3ada8907e78",
    "0326e692c455dd554c709bbb470b0ca7e0bb04152f777d1445fd0bf3709a2833a3",
    "03a93b87bf9f052b8e862d51ebbac4ce5e97b5f4137563cd5128548d7f5978dda9",
    "033b63e4a9931dc151037acbce12f4f8968c86f5655cf102bbfa85a26bd4adc6d9",
    "0203e5b16ebe87b089f22e18752f1f7a66a1bdf77879df8d1c9e8d912dbfb9beb4",
    "02f460ae6d3d3e104f8afe520ae0cff3d94c35c2ba8df66da89f3c8006a265b90a",
    "033d9e73a183c9714545f292875fb90c4372bddc9c2cc302b265d15e7969a5ed60",
    "03ec512342aeee370b53d9fd12dbd5283dcd670d248018b3a1cf537313e76e6a2d",
    "037f990e61acee8a7697966afd29dd88f3b1f8a7b14d625c4f8742bd952003a590",
    "039cdd937f8d83fb2f78c8d7ddc92ae28c9dbb5c4827181cfc80df60dee1b7bf19",
    "02dfe525d9c5b4bb52a55aa3d67115fa4a6326599c686dbd1083cffe0f45c114f8",
    "027ce055380348d7812d2ae7745701c9f93e70c1adeb2657f053f91df4f2843c71",
    "02bce4f7ae5b2d51c18575b3f277e296d9df800a54d749d7a3145c9e40237e4011",
    "02a0f17d3ddb81b3b0c048956baebdf68468c9d7c8b851e5d26354a64a54cff562",
    "03dc686001f9b1ff700dfb8917df70268e1919433a535e1fb0767c19223509ab57",
    "03f5dcf253ca5ab4a8a0ad27bc5d8787ca920610902425b060311530cb511e9545",
    "037f66e84e38fc2787d578599dfe1fcb7b71f9de4fb1e453c5ab85c05f5ce8c2e3",
    "0261239197442bda65c9933359bbcba72e89f3e77ca87edd7be2e4bf7ba9218117",
    "03f94b8e82c3c9be8f8d1e3bcb595e2855b72f23b92967c26f7d65be9a75184c12",
    "029efe15ef5f0fcc2fdd6b910405e78056b28c9b64e1feff5f13b8dce307e67cad",
    "034a879c36f418cb5b44b6903b3c6c1cfb5f4beb1e79b9b479c040b7df9cbc56be",
    "03011e480a671ac71dbc3fc3e8fe0db32bb9a10cc4d824663e09557d446ef80679",
    "037e27d212432eaf499e4fb648d996944f3454c094dab36336bac573f82211a335",
    "0298f6074a454a1f5345cb2a7c6f9fce206cd0bf675d177cdbf0ca7508dd28852f",
    "0294ac3e099def03c12a37e30fe5364b1223fd60069869142ef96580c8439c2e0a",
    "034ea80f8b148c750463546bd999bf7321a0e6dfc60aaf84bd0400a2e8d376c0d5",
    "03e81689bfd18d0accb28d720ed222209b1a5f2c6825308772beac75b1fe35d491",
    "03b006c37dfb8681e5db9f513386d06c9d18bd514fae5d79a7ed2d5991c7d57330",
    "025e9497188d33af48bb15cfc3cd6d7c549eed05b5f54d45615d3cb7ec3b562588",
    "033dee9c6a0afc40ffd8f27d68ef260f3e5e1c19e59c6f9bb607fb04c1d497a809",
    "0288be11d147e1525f7f234f304b094d6627d2c70f3313d7ba3696887b261c4447",
    "0334bbf89f5fc82c8aebbddc9f2b78f9528cd2fd916fbc091a8ce35aed57c1110d",
    "033d8656219478701227199cbd6f670335c8d408a92ae88b962c49d4dc0e83e025",
    "03e9c99fddf5aaa60e22c166622206947b1fb14ae2926f550f837af6aa83556bb8",
    "03afa7a8196dbca763ee6f9a34b634a7adc03f154e5d6979fe654db5606b5fb2b1",
    "0250baf7a558091eb9c93f43d595b795db61bd2b55ca016d8682fd310cb1b81e6c",
    "031633471d005f37252ede8114c6f4203e0a668270532f0f11a1e4072eb2eef272",
    "03037dc08e9ac63b82581f79b662a4d0ceca8a8ca162b1af3551595b8f2d97b70a",
    "03d06758583bb5154774a6eb221b1276c9e82d65bbaceca806d90e20c108f4b1c7",
    "03641a88d80a2a85bbecd770577aca9b5495616e9fef63d66ef2631b7cca1d395d",
    "037659a0ac8eb3b8d0a720114efc861d3a940382dcfa1403746b4f8f6b2e8810ba",
    "03abf6f44c355dec0d5aa155bdbdd6e0c8fefe318eff402de65c6eb2e1be55dc3e",
    "02e9046555a9665145b0dbd7f135744598418df7d61d3660659641886ef1274844",
    "035542f0f213a5b6e985dff0e0fd973da01bd77325d44242fc325d0ea8eea3d312",
    "0299797daa21faa6e4151517b286c41d4c7a8cb21fbfba59ca3bcd21a9f8392bd4",
    "026e44acf41fcfa19d092a297a7e8452f6ac5eee677ed0f7f2e5d4c7c632467224",
    "02f4c77dcf12255ccf705c18b8d6b95e4f884910bf61e8aa21242607193a79da1b",
    "021fa607f2b6ceebe5742aaa7650cf817351e7d70cf47595a48ffd2e5741076b06",
    "03362ab599d1e8d5e8e02ce38e836a3cf1a6e59f047d7f02d12484f160a6bc76f6",
    "037c65e34444c37deaccde1f61f03b93e22b3d7451894d836f60132ee5a6f486ed",
    "0289753f4559770003baec773453f8d1b2dfae3256546891e4cfef3a0bdbaa4f30",
    "03bd6d28432d67effa2b2b89dd5fd68697940e8a8f2fbb84aaae90d584295b03bf",
    "0335bd24a733d623205f30452c485de9c39ac3135f57679574a49a3add6bb1a050",
    "03b4b86f2301fe2b9ca478ee5980d812de2071a21a9f8f5bb49b88e29a034e1a9b",
    "031c7ecff228dfe6054307ee49c8616998af5f8d4436f13c07d211aeb6c0ec87f7",
    "0293a4a5933422fa7cae2c8ff4c44490f26cf3dd7ac02b826ee20d4cba7dac944d",
    "0242c1650f320c43f3600ebf3b5fcaf566760fcd421f35b68fd1e39a31b29ef540",
    "023d49fd88692d4d1f366ee8ffa9dfe979c2266b036b440928e86cf3abe28d1894",
    "0391e2edea5191627a25ecbd327c0dc2a95c880a5b0e73af38dc4a5a8964263b3f",
    "02ac10d3b0a3da8434898323f75b97281e157fd858c2fb761d1994941aac515d1c",
    "033d38e07e2541628214c8184cf6c562311059872363e9f538b2f45434418b5bc5",
    "03d35779ff612c574b92494d74300ce467e0eb510181a6ae3eb74d8ada891d82aa",
    "03c72f89b660de43fc5c77ef879cbf7846601af88befb80e436242909b14fd0495",
    "023cd6704ce78644a568fbd993f65dc76fb1bf8bcce4c912930447c71d0c2698ad",
    "0380030304baea090616a296674b6ae337a138593b5390266a45a17eef7a62a2b0",
    "03d6f80df785288de2fe5de19f24ba8a1db3d20647a88d0a903be9de3e7bb8fce1",
    "021f98b9898720f8633c93faf0aa54ab399d277464e502d1111b233c2cf4064828",
    "022618bb95c7cd788a4f2d54e638d73212ffce867e1714734b2b65bac5274635ad",
    "0208dfa005c47a8ae85363d12c54007a38550ca0d6f1c559ee11caaac8221eccd6",
    "0317983322379d859c0d43a90c8dcd3e7239b8e0671b00a657ce3924d4498f3754",
    "02439112f98b6f4828e1a7426bfbece166bd36837d7dea4225a75ebd1d96864a07",
    "0379221a4051d4171490e43e4a09e218a02941f06996b71cd814b290da08ad5f7e",
    "02b21ca992bf95e3f324302265ad86cec24f36166fd7afca44efa0809aaa8b25c5",
    "0380ef0209ff1b46c38a37cd40f613d1dae3eba481a909459d6c1434a0e56e5d8c",
    "0385b81d9661adf36c086be5217a03c29a4276c0b5c9e607c745a239bba430d63f",
    "0260fab633066ed7b1d9b9b8a0fac87e1579d1709e874d28a0d171a1f5c43bb877",
    "0340cfadaa3324e0dd176a9969be050114278f93260e1b6333bd2a2a2ea03c64a3",
    "02bb10aaa77a95a358cebb2d112c4de00e47c08f56e89b1acb4487ddd44cc98d6d",
    "03d2e20bc19d995098ba357157a9cfbfbfdff4b78fce5ec713128e988e0115d776",
    "030a58b8653d32b99200a2334cfe913e51dc7d155aa0116c176657a4f1722677a3",
    "02ec20f34bb94460f3d63780dfc24a4d4a1ddabc3bd86c09e1830c5b5db08953e5",
    "02ff30e83896d453cfc89ff4dd06d23d793b7246f154c210324adc1d42c849ce74",
    "02d695b01c7a6909e716c863fb39bc5fb7bbdc3824b7fdce53adc593e5be080e73",
    "0340f8fa6bc058df204691bc1c965de041e550d8ef0512d22007d4cab7ebd7a536",
    "03ef1f35c48695828f614ac685fd5eead1005641cac453ed31052b0ef6cb959a60",
    "03c792f6a89fefd3f1b49b3d2ce23143b6f18d36b2ccb039fdb7dbfeb29159bb70",
    "0229ec1dfd9ae232fcd75e49a4f1112a59f688705e25ecbcc0d56e15a3994c9dfe",
    "03aab7e9327716ee946b8fbfae039b0db85356549e72c5cca113ea67893d0821e5",
    "026af41af0e3861ba170cc0eef8f45a1015125dac57c28df53752dcaeea793b28f",
    "03f3643570433b67f22ef1c2e7660e33c9b9d53f786cb1779544983aa5c8f286e3",
    "0337694505123a12a8fadd95523dcc235898ad3b80a06e4a63ca26fed68dd0d17c",
    "036eb65676a65660e4c1ffd728d88b3d82d027d416fad59867471fe2123de0ab27",
    "023e09c43b215bd3dbf483bcb409da3322ea5ea3b046f74698b89ee9ea785dd30a",
    "03e9cbcd46bd7de2a1559777e7f0c6681522a9b1821b994923da748e06b796cab0",
    "02916bb52b33836e28a3649baea2e4a29c16fd8ad97901b2c97d408f428edef108",
    "02826f50035eca93c7ebfbad4f9621a8eb201f4e28f994db5b6b5af32a65efb6b9",
    "039311d5a11e1df479bfc695b09127f7920e66dacfb19f0ef20a28a2a7959f0080",
    "026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2",
    "03a465772d45616bf6c8450a69191db8f3cf8cca19ff92138735fd5f1d436fe4dc",
    "03bcf1f73199ed4445a8d6c033dd8cb550bb5205a16982ad2e13359e3318498c02",
    "0204a91bb5802ad0a799acfd86ef566da03d80cc9e13acb01e680634bf64188a0d",
    "02fcc5bfc48e83f06c04483a2985e1c390cb0f35058baa875ad2053858b8e80dbd",
    "02ad4afb6e50ae4635ec5ddf5a57c44d4cc4b376ac6580f78cda0454a86e5fa6c2",
    "02bc400b9df471549c1a2071a61be27460e9726d3399370671514dd8356606bd81",
    "02fb79c3a9121d85b126687bd111eaebf21aaaaa5cbf232e2b6c3bdf8803f40182",
    "02fe6a27ddcb2dd9fa8479fe1d52549b5932079a493b51f1409fa2c5878f1bc07c",
    "0351fabd839e93962826ab8eff7f86795b66b7295a2330773938d409a725aa8176",
    "02c91d6aa51aa940608b497b6beebcb1aec05be3c47704b682b3889424679ca490",
    "03df3f0a2fd6bea5429a596461ce784c922b2981ada1af89cfefcd9ccfb16c16a7",
    "033533e2db6311c1d417d41279c067d8713ad8a7d577a0d91e65df2f6a82c5b862",
    "035360b3bf6a997ed1bb943ccca2b7ef969b1e25a1ee1322d3c8acca7e34468edd",
    "0254bb156ecd0eac318844415a91a377bc6947ea4c9fbe5d248e563c29a1662835",
    "0333175e2ddb8ae3fab14125c312cf62b9da6dc54fc922edd1aa11e4e059496594",
    "0288f320d25b20df0578af737ea951c1c3adcc4e8cd908d5a291bddc49981a1cdf",
    "03bc77779d860e8b231d307c109bee12fa8f7949ca01273f296548fbe50c063dad",
    "033b277b17cf7c70fd4de5cbe8dcaeda0cd63d44fcd680f82f76dcac2ebad10c2f",
    "021f1beed0a32fb740e9c8ea12702dd4371b444a6464368d93a2957b95f8cd2db1",
    "02f63f49339c8b438c3291ab21e35d1b5642ac2360240068b5ecd3fd5183f2c042",
    "021a7a31f03a9b49807eb18ef03046e264871a1d03cd4cb80d37265499d1b726b9",
    "036b53093df5a932deac828cca6d663472dbc88322b05eec1d42b26ab9b16caa1c",
    "036508f7e82bb78bad307cfacf4edf850fc3f20ca071eaa8074d9d5424a9092c0b",
    "023662f1db3d0527dab0869e30f183021db7dc44f6f2e32ece42dd124846c89ca1",
    "02aace31b8120e29cfc29d991b63fe8614cddd3fbf6148431cc3a68932c363ed29",
    "03e86afe389d298f8f53a2f09fcc4d50cdd34e2fbd8f32cbd55583c596413705c2",
    "03cde60a6323f7122d5178255766e38114b4722ede08f7c9e0c5df9b912cc201d6",
    "030995c0c0217d763c2274aa6ed69a0bb85fa2f7d118f93631550f3b6219a577f5",
    "035fed4182fbd0725264f8a0018cabb6b25514dd231291162ac8dd63afb278e9e8",
    "03501a74753e0f6ae270a1e4e2ffbbc37f7a796360e650c1121c18e116b22ac106",
    "02343c19a39dd11cfc6f7571f36213dd52fb70ee45ee4074913d43891fb59579b5",
    "028ed7bd6ba6763cf040869681890bf5bf95d623108a60e75d76a57f5d637be3ef",
    "0285d50bc04a6a7eaeb37c4964d5f1322b1136c8cea2f242d3c52302226043cbe4",
    "03f80288f858251aed6f70142fab79dede5427a0ff4b618707bd0a616527a8cec7",
    "03f632d57f9c1ad729695f2c8c958b8d1d0b765fc99ea6f3fbe41b039397c49938",
    "029b81d1aaf177fa00c1c5796360163bfa98ee4d5d0daa54c6f510d9e237f376e9",
    "03127747aa9fb9b4813b7ebdd6ac47eb047954513ab06fe909689c2c42eaa49a33",
    "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f",
    "020c92d71dfe47d49d322eed910064787973dff96c05a39d75a75d7e8f33aead4c",
    "02abfbe63425b1ba4f245af72a0a85ba16cd13365704655b2abfc13e53ad338e02",
    "03c157946cc1cd376b929e36006e645fae490b1b1d4156b40db804e01b4bda48cd",
    "026209a739dbf4ab8c73db56773a61247e92fecc53ec5c8f7ae41f6d11fec64a04",
    "03d4e028a0d4a90868ec202ab684fb0085779defea9ca7553e06146557631eec20",
    "021c3ec6432d2b9b5abcb01dd64b3a8f2afe3ba7d8c021f63ffd0a994cd3bc9b88",
    "027ecdd3c509f7db2d8ade67381bb2e8ed88ccbfab8805d24076c4a0fd131f71ff",
    "03f6ceaa67db2cc169fb8f74b762211e3ce20459bac52ac7f8c85f351670a6b678",
    "02df5ffe895c778e10f7742a6c5b8a0cefbe9465df58b92fadeb883752c8107c8f",
    "03cb68051b6faeda941420819446a9429053223a465d370642b2a88336c43b02dd",
    "03d83d26813669d8665d6a5017ecd18d176db0893f00f39e0a38493a1b6e3bbcd7",
    "0387d57be12709c8745bc35ac3dfc22611a944a12bcc1fe49a55d7c9bafea335f9",
    "025022f660d278b8d90415bdde1b385841b6caf179dc69569e4b55fd5aec70555f",
    "03f10c03894188447dbf0a88691387972d93416cc6f2f6e0c0d3505b38f6db8eb5",
    "02b515c74f334dee09821bee299fcbd9668182730c5719b25a8f262b28893198b0",
    "0305f5f4013f6c6eeb097bd8607204ec1f31577a05fae35f0d857c54d3b52e4e45",
    "02a2106a4681d68080cf3d8a3b706d6925142aee0caf99302e481dbb08feabfa1a",
    "031015a7839468a3c266d662d5bb21ea4cea24226936e2864a7ca4f2c3939836e0",
    "03676f530adb4df9f7f4981a8fb216571f2ce36c34cbefe77815c33d5aec4f2638",
    "036d89937841b3d34b70bc1e515dedd1082db048459733e3d3c62d7bca97fbf33e",
    "0355b39fb472045743c767e1f8de60128b9a68deeb5a834f343ed4968cf0193fc7",
    "02e2d1b40f08d2ca704c7f62397eec42245cb394d4a07db695ac5348dd24a527bd",
    "03dd09855c3634daa5c7de0146f4d54eb395b51ae422bc86ee1132a0d7ed50e720",
    "03698a61657d54ef3d43aff229da7037bdbea27654ed7fc043b439265132c52354",
    "02478e2fc963f74d0557a4bd821a743b18d51bbb589bfa124edf39aec95a65fc35",
    "024509d6321a579b3f72117509e243d6cdd86874cb0731ff39be6c92f3e64b53a1",
    "030ed412981860150762a3ec93d9e571442cbc0f2f7d3be1b3d047d7695e94c0c4",
    "035b1ff29e8db1ba8f2a4f4f95db239b54069cb949b8cde329418e2a83da4f1b30",
    "0296b2db342fcf87ea94d981757fdf4d3e545bd5cef4919f58b5d38dfdd73bf5c9",
    "03bb88ccc444534da7b5b64b4f7b15e1eccb18e102db0e400d4b9cfe93763aa26d",
    "02c73c8ac3f37bb28d9fc3819dc17baecdf24b137d476a2a9e22395d490d842bec",
    "03627ebe50fc6eb80b0caab0c3714958c701eda735e3c29588e83150d6d4a93976",
    "032434517e28f7b51665a525d5e11fa493bd4e30a59883b8156c2be4085f4aaf70",
    "0324ba2392e25bff76abd0b1f7e4b53b5f82aa53fddc3419b051b6c801db9e2247",
    "02758d961750972030292701d85c90e332bc1b7d8db0e705df3f087d285f9caf06",
    "03797da684da0b6de8a813f9d7ebb0412c5d7504619b3fa5255861b991a7f86960",
    "032a54b1e9cd2ff8ec5f58915a749cf074e957006e8b4da9c8497fed4b6c6f88dc",
    "021c97a90a411ff2b10dc2a8e32de2f29d2fa49d41bfbb52bd416e460db0747d0d",
    "0293e0945e225ebb21daaa846ccfc8f3f2c5e97421bed2b7f9d1fb11d96b8a3bf3",
    "02d3f41e090bd5b52eed0a9288705b248eb27afe995f02840cb8e7a2abc72580e2",
    "02c29b89b2121b2c1fa2e5422bc70e0bb7ae7326c7a9d2b796ed6b89cdc5a2871b",
    "0381499873090f47c7f857b90a91a5de4708054b5966904e0623023c9a5ad0e8a1",
    "0369a6185476b5d0372f526bc99d7614ff83fc0bfb11821b6e3c978ee64bcc865c",
    "0236333aacf54604abf218af6ab116d4fe6f16e527502e0019123d0cc3c7a8a194",
    "03f2005837649dd49811bbb7e78993581da41c09d3bdcbc6933492276acccd8b6d",
    "02e5544cda426d1dac8e5237e32eec59cbf93b88b76ef94ee7ecf8f76a5358fbbf",
    "0356c1091bb139ad3520eb370f1512ac2f4ed67b87d2687638252152fbf2b4575f",
    "021e9cd0d5417970eb15bfcda0b7628c8f49ef710603577776fa45c5b8ecbca35e",
    "03ef684e8c2ec25ea1a95fa46729e3355dd90210e0c57bad502d60676098ec83b3",
    "02a7792c657562b66bc87e5a2b98d32e8cd9fc16fab40cb67124472bf6b470beb8",
    "02fe3bf758f87d9b0cee6bdafa52d04650daea8c48f7178358b130b62e132c6f5f",
    "026d665c34210fd99f9d4be36bcfbd7d637ae890631274d1f82cbf45af8cd8b2c6",
    "03d6b14390cd178d670aa2d57c93d9519feaae7d1e34264d8bbb7932d47b75a50d",
    "021f0f2a5b46871b23f690a5be893f5b3ec37cf5a0fd8b89872234e984df35ea32",
    "03e472ddc37b014ce7d5f942b00b28fb1db53d461c4a89173962abd4b331a85179",
    "03e046abe9c7e7f963adf989c128fe187e59890314d0a30653a4498b13d197911c",
    "038ec8cd65fb69e147c2bd6de83f2ba57e312764cbeac2f594ae68d6b9c174f019",
    "03019e830b31e86befd057246e078933520a77bb93d2bb7923d4aca7682a845c45",
    "03a32622b5350eea6c5bb16a73ddfa07af452b17b47f0d2ec7d33db884fe074d83",
    "022eb09a7993a0edde69537b420f4119c0de833e0ee47651753b46bf884db75235",
    "02d0e03736cbfc73f3c005bc3770327df0e84bd69bc8e557c279887344deb8bce2",
    "029267159e8ed64dc44f1deda34c918f45c7ba2d6b2533a2c1083a2d15f5f4330a",
    "031f2669adab71548fad4432277a0d90233e3bc07ac29cfb0b3e01bd3fb26cb9fa",
    "028d98b9969fbed53784a36617eb489a59ab6dc9b9d77fcdca9ff55307cd98e3c4",
    "026ec3e3438308519a75ca4496822a6c1e229174fbcaadeeb174704c377112c331",
    "03a01da97af71f7859cd1b2b6a70f221ecd49f6eabf0bf1e267bae9570b47232a6",
    "028f4a60dd133875e8776d5ac36e87097cf59e6e3a1d74fcd14c900270dda57c06",
    "0289b70b52a04e951446674bedb571336295a2890ca0079639ebc067076277d571",
    "03fbe1c1baedbc99b2642ae524d9c2a6f12b771a3ab91e0f56ca6efc6f7f7d53b6",
    "036cb1a035eb1c7f125c004ed046d329285bd57e4100f18b577af721659becd832",
    "03820714a3f891c7c3ae5e00dbdd77f06ceccc24ddd8c99fadef13ec2eec462cce",
    "03808b1a698906bbf0457922aec66168a8edbfe98b1379249ace270b41ae0dde48",
    "0385218f0e307b6a0e989d2a717d346942d96b4fd550e937de5f8ffe1568510a18",
    "029a0f8111f0bcb94003413838451dfc1d0faed030ef46ff84d96c0dc5be3d1415",
    "020f7c502e19ccb375d4abc689f2c1feb6816961d4a1e2dcfa8813f11c3bc9a5e1",
    "024271a1be2d7a3e2a276b241257be734d843885d252f50575e4c7db2691aedd3a",
    "0201bfc5d9c14d50ebaf4dfd83d70df314ed2a9f0119f28619f3f000a1079ef580",
    "021ecaf18c177e308009b9bdbf0d6784536e027759f797d64300787a24e6528a7c",
    "03271338633d2d37b285dae4df40b413d8c6c791fbee7797bc5dc70812196d7d5c",
    "035eb7d2253d934b51dd1cc145b6f36a9c2d953c4379f5fff9c39bb437ece525ae",
    "03ac61c971d146787a036f75e80a9fbede238a75d0c396f1fe996def00f0ac5dbe",
    "0282888287c371a97b5e735ae21f85c80351c492741d57c96e43806e3654904262",
    "03284f74651198c2c35952a8e0204e68a824455f329f799c1368feb850572036e9",
    "02bc320249b608a53a76cf3cbd448fdd3ab8f3766f96e8649c2edc26cf03bf8277",
    "02918715f4981723ec82c3d7f50f6bf927a9145e592e9997cd7a97c87ef6bc7602",
    "03c65f59676fcb31951fe4c610f3a17612dc5a5c35d1f03733468e19277aad6f6b",
    "02c4ae20674d7627021639986d75988b5f17c8693ed43b794beeef2384d04e5bf1",
    "023369b071005d376bfa94b76d2ec52d01d6709f57d6b67bf26250f2ef57a66aea",
    "03193aa3b4db3ecb2025395e704e8e808f412914beb629270f7b902b9460539400",
    "03606d67d00ce06ad053de1f755e6f6c8185ae66a1b1e06ec7b72e2ef702690d5f",
    "0349cb2f33d5542432b016405a22dfda18617d87abe4718e61c45909b8a5449329",
    "021c4c58a15fa847720cbc02775df975c1dd6994be443f6eb1392275559c05db7f",
    "03d607f3e69fd032524a867b288216bfab263b6eaee4e07783799a6fe69bb84fac",
    "0231eccc6510eb2e1c97c8a190d6ea096784aa7c358355442055aac8b20654f932",
    "02db3bce6ad28505ec56254e3c27b912f3d3723d7573e3b4174368b80ebf8f2ba8",
    "026a0ae3ca9ff56a7d38e861022e3805c43f9285720d0990c9fe91eb494287f052",
    "027100442c3b79f606f80f322d98d499eefcb060599efc5d4ecb00209c2cb54190",
    "03391210b7fd47678df727ed7c39ea2f3c8dd43d6fb747582b1c13d4c1376f4714",
    "02c717cf27420cb5efc492921851c6c5b328502c37a9fd282d5d2f04364e466768",
    "030c6ace90f74ea293519469084a077ea49692e147b4d9c881b62c85f676d79eb4",
    "03f171125a76de0c957341488156993e3e6a603366021da31ef5811812b4881c81",
    "03a8b61013b27176c441cb7b6875b159d9dc1c270651e603447e93d5bbc78ffaa6",
    "038c5b2d6a0fe180d1be557d49f7f982190957edf20a4c05a305d7aed17c156ef0",
    "027e9c96bf2a2d9b5f9002bc4d4e4765ab525e4e1fb1ada702a4a64a1b40ccdb9d",
    "0325de5af4666d0ceee17c805817d02159fb2bc67f84c333372183b037294ffb2c",
    "020af8a7428f99ce4510e523031e2078c065c1097a48c860ae2cdd3511c8b7627d",
    "03b211f8a4a9cd40c9a1b5626bb8b0f1ca66b36e6b4fddd2723c67683d6f8d1ec7",
    "02ee60fef298e59b2ae4ff09642a62a1317c7baac97d51b1fc7e5581d1c6fef695",
    "0246ee8e4c965296799eebd29a0948b9a4641843298b0f2a8e42256c4b594e4b8f",
];

fn build_preferred_hubs_set() -> HashSet<NodeId> {
    PUBKEYS
        .iter()
        .map(|pubkey_str| NodeId::from_str(pubkey_str).expect("only pubkeys involved"))
        .collect()
}

pub type ProbScorer = ProbabilisticScorer<Arc<NetworkGraph>, Arc<MutinyLogger>>;

pub struct HubPreferentialScorer {
    inner: ProbScorer,
    preferred_hubs_set: HashSet<NodeId>,
}

impl HubPreferentialScorer {
    pub(crate) fn new(inner: ProbScorer) -> Self {
        Self {
            inner,
            preferred_hubs_set: build_preferred_hubs_set(),
        }
    }

    fn is_source_preferred_hub(&self, candidate: &CandidateRouteHop) -> bool {
        match candidate {
            CandidateRouteHop::FirstHop(_) => false, // source of first hop is us
            CandidateRouteHop::PublicHop(hop) => {
                self.preferred_hubs_set.contains(hop.info.source())
            }
            CandidateRouteHop::PrivateHop(hop) => {
                let source = hop.hint.src_node_id;
                let node_id = NodeId::from_pubkey(&source);
                self.preferred_hubs_set.contains(&node_id)
            }
            CandidateRouteHop::Blinded(hop) => {
                // we can prefer blinded paths with hub introduction points
                let (_, path) = hop.hint;
                let node_id = NodeId::from_pubkey(&path.introduction_node_id);
                self.preferred_hubs_set.contains(&node_id)
            }
            CandidateRouteHop::OneHopBlinded(hop) => {
                // one hop is just the introduction node which is a known node id
                let (_, path) = hop.hint;
                let node_id = NodeId::from_pubkey(&path.introduction_node_id);
                self.preferred_hubs_set.contains(&node_id)
            }
        }
    }

    fn is_target_preferred_hub(&self, candidate: &CandidateRouteHop) -> bool {
        match candidate {
            CandidateRouteHop::FirstHop(hop) => self.preferred_hubs_set.contains(hop.payer_node_id),
            CandidateRouteHop::PublicHop(hop) => {
                self.preferred_hubs_set.contains(hop.info.target())
            }
            CandidateRouteHop::PrivateHop(hop) => {
                self.preferred_hubs_set.contains(hop.target_node_id)
            }
            CandidateRouteHop::Blinded(_) => false, // the target of a blinded path is unknown
            CandidateRouteHop::OneHopBlinded(_) => false, // the target of a blinded path is unknown
        }
    }
}

impl ScoreLookUp for HubPreferentialScorer {
    type ScoreParams = ProbabilisticScoringFeeParameters;

    fn channel_penalty_msat(
        &self,
        candidate: &CandidateRouteHop,
        usage: ChannelUsage,
        score_params: &Self::ScoreParams,
    ) -> u64 {
        // normal penalty from the inner scorer
        let mut penalty = self
            .inner
            .channel_penalty_msat(candidate, usage, score_params);

        let hub_to_hub_min_penalty = (score_params.base_penalty_msat as f64 * 0.5) as u64;
        let entering_highway_min_penalty = (score_params.base_penalty_msat as f64 * 0.7) as u64;

        let is_source_preferred_hub = self.is_source_preferred_hub(candidate);
        let is_target_preferred_hub = self.is_target_preferred_hub(candidate);
        if is_source_preferred_hub && is_target_preferred_hub {
            // Both the source and target are on the "hub highway"
            penalty = penalty.saturating_mul(5).saturating_div(10); // 50% discount
            penalty = penalty
                .saturating_sub(HUB_BASE_DISCOUNT_PENALTY_MSAT)
                .max(hub_to_hub_min_penalty); // Base fee discount
        } else if is_target_preferred_hub {
            // Only the target is a preferred hub (entering the "hub highway")
            penalty = penalty.saturating_mul(7).saturating_div(10); // 30% discount
            penalty = penalty.max(entering_highway_min_penalty);
        } else if is_source_preferred_hub {
            // Only the source is a preferred hub (leaving the "hub highway")
            // No discount here
            penalty = penalty.max(score_params.base_penalty_msat);
        } else {
            // Neither the source nor target is a preferred hub (staying "off the highway")
            penalty = penalty.saturating_mul(15).saturating_div(10); // 50% extra penalty
            penalty = penalty
                .saturating_add(HUB_BASE_DISCOUNT_PENALTY_MSAT)
                .max(score_params.base_penalty_msat); // Base fee penalty
        }

        penalty
    }
}

impl ScoreUpdate for HubPreferentialScorer {
    fn payment_path_failed(
        &mut self,
        path: &Path,
        short_channel_id: u64,
        duration_since_epoch: Duration,
    ) {
        self.inner
            .payment_path_failed(path, short_channel_id, duration_since_epoch)
    }

    fn payment_path_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
        self.inner
            .payment_path_successful(path, duration_since_epoch)
    }

    fn probe_failed(&mut self, path: &Path, short_channel_id: u64, duration_since_epoch: Duration) {
        self.inner
            .probe_failed(path, short_channel_id, duration_since_epoch)
    }

    fn probe_successful(&mut self, path: &Path, duration_since_epoch: Duration) {
        self.inner.probe_successful(path, duration_since_epoch)
    }

    fn time_passed(&mut self, duration_since_epoch: Duration) {
        self.inner.time_passed(duration_since_epoch)
    }
}

impl Writeable for HubPreferentialScorer {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.inner.write(writer)
    }
}
