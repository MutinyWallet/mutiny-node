use crate::error::MutinyError;
use bitcoin::Network;
use core::cell::{RefCell, RefMut};
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use futures::{
    future::{self, Either},
    pin_mut,
};
use lightning::routing::scoring::{LockableScore, ScoreLookUp, ScoreUpdate};
use lightning::util::ser::Writeable;
use lightning::util::ser::Writer;
use reqwest::Client;

pub const FETCH_TIMEOUT: i32 = 30_000;

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
        tokio::time::sleep(Duration::from_millis(millis.try_into().unwrap())).await;
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

pub async fn fetch_with_timeout(
    client: &Client,
    req: reqwest::Request,
) -> Result<reqwest::Response, MutinyError> {
    let fetch_future = fetch(client, req);
    let timeout_future = async {
        sleep(FETCH_TIMEOUT).await;
        Err(MutinyError::ConnectionFailed)
    };

    pin_mut!(fetch_future);
    pin_mut!(timeout_future);

    match future::select(fetch_future, timeout_future).await {
        Either::Left((ok, _)) => ok,
        Either::Right((err, _)) => err,
    }
}

async fn fetch(client: &Client, req: reqwest::Request) -> Result<reqwest::Response, MutinyError> {
    client
        .execute(req)
        .await
        .map_err(|_| MutinyError::ConnectionFailed)
}

pub fn get_random_bip32_child_index() -> u32 {
    let mut buffer = [0u8; 4];
    getrandom::getrandom(&mut buffer).unwrap();

    // Convert the byte buffer to u32
    let random_value = u32::from_le_bytes(buffer);

    // Restrict to [0, 2^31 - 1]
    let max_value = 2u32.pow(31) - 1;
    random_value % (max_value + 1)
}

pub type LockResult<Guard> = Result<Guard, ()>;

pub struct Mutex<T: ?Sized> {
    inner: RefCell<T>,
}

unsafe impl<T: ?Sized> Send for Mutex<T> {}
unsafe impl<T: ?Sized> Sync for Mutex<T> {}

#[must_use = "if unused the Mutex will immediately unlock"]
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: RefMut<'a, T>,
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.lock.deref()
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.lock.deref_mut()
    }
}

impl<T> Mutex<T> {
    pub fn new(inner: T) -> Mutex<T> {
        Mutex {
            inner: RefCell::new(inner),
        }
    }

    #[allow(clippy::result_unit_err)]
    pub fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        Ok(MutexGuard {
            lock: self.inner.borrow_mut(),
        })
    }
}

impl<'a, T: 'a + ScoreLookUp + ScoreUpdate> LockableScore<'a> for Mutex<T> {
    type ScoreUpdate = T;
    type ScoreLookUp = T;

    type WriteLocked = MutexGuard<'a, Self::ScoreUpdate>;
    type ReadLocked = MutexGuard<'a, Self::ScoreLookUp>;

    fn read_lock(&'a self) -> Self::ReadLocked {
        Mutex::lock(self).expect("Failed to lock mutex")
    }

    fn write_lock(&'a self) -> Self::WriteLocked {
        Mutex::lock(self).expect("Failed to lock mutex")
    }
}

impl<S: Writeable> Writeable for Mutex<S> {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        self.lock()
            .expect("Failed to lock mutex for write")
            .write(writer)
    }
}

impl<'a, S: Writeable> Writeable for MutexGuard<'a, S> {
    fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
        S::write(&**self, writer)
    }
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

/// Returns the version of a channel monitor from a serialized version
/// of a channel monitor.
pub fn get_monitor_version(bytes: &[u8]) -> u64 {
    // first two bytes are the version
    // next 8 bytes are the version number
    u64::from_be_bytes(bytes[2..10].try_into().unwrap())
}
