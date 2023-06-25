use bitcoin::Network;
use core::time::Duration;

pub(crate) fn min_lightning_amount(network: Network) -> u64 {
    match network {
        Network::Bitcoin => 50_000,
        Network::Testnet | Network::Signet | Network::Regtest => 10_000,
    }
}

pub async fn sleep(millis: i32) {
    #[cfg(target_arch = "wasm32")]
    {
        let mut cb = |resolve: js_sys::Function, _reject: js_sys::Function| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
                .unwrap();
        };
        let p = js_sys::Promise::new(&mut cb);
        wasm_bindgen_futures::JsFuture::from(p).await.unwrap();
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::thread::sleep(Duration::from_millis(millis.try_into().unwrap()));
    }
}

pub fn now() -> Duration {
    #[cfg(target_arch = "wasm32")]
    return instant::SystemTime::now()
        .duration_since(instant::SystemTime::UNIX_EPOCH)
        .unwrap();

    #[cfg(not(target_arch = "wasm32"))]
    return std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap();
}

pub fn spawn<F>(future: F)
where
    F: core::future::Future<Output = ()> + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::task::LocalSet::new().spawn_local(future);
    }
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(future);
    }
}
