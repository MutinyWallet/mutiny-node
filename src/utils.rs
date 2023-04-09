use bitcoin::Network;
use core::cell::{RefCell, RefMut};
use core::ops::{Deref, DerefMut};
use core::time::Duration;
use instant::SystemTime;
use lightning::routing::scoring::LockableScore;
use lightning::routing::scoring::Score;
use lightning::util::ser::Writeable;
use lightning::util::ser::Writer;
use lightning_invoice::Currency;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

pub async fn sleep(millis: i32) {
    let mut cb = |resolve: js_sys::Function, _reject: js_sys::Function| {
        web_sys::window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
            .unwrap();
    };
    let p = js_sys::Promise::new(&mut cb);
    wasm_bindgen_futures::JsFuture::from(p).await.unwrap();
}

pub fn currency_from_network(network: Network) -> Currency {
    match network {
        Network::Bitcoin => Currency::Bitcoin,
        Network::Testnet => Currency::BitcoinTestnet,
        Network::Signet => Currency::Signet,
        Network::Regtest => Currency::Regtest,
    }
}

pub fn network_from_currency(currency: Currency) -> Network {
    match currency {
        Currency::Bitcoin => Network::Bitcoin,
        Currency::BitcoinTestnet => Network::Testnet,
        Currency::Signet => Network::Signet,
        Currency::Regtest => Network::Regtest,
        Currency::Simnet => Network::Regtest,
    }
}

pub fn now() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
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

    pub fn lock(&self) -> LockResult<MutexGuard<'_, T>> {
        Ok(MutexGuard {
            lock: self.inner.borrow_mut(),
        })
    }
}

impl<'a, T: 'a + Score> LockableScore<'a> for Mutex<T> {
    type Locked = MutexGuard<'a, T>;

    fn lock(&'a self) -> MutexGuard<'a, T> {
        Mutex::lock(self).expect("Failed to lock mutex")
    }
}

impl<'a, S: Writeable> Writeable for Mutex<S> {
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

/// Returns true if the given network is valid for the given destination network.
/// This is used to prevent users from sending funds to the wrong network.
/// We can't just compare the network directly because signet and testnet
/// have conflicting address prefixes.
pub(crate) fn is_valid_network(my_network: Network, dest_network: Network) -> bool {
    match (my_network, dest_network) {
        (Network::Bitcoin, Network::Bitcoin) => true,
        (Network::Testnet, Network::Testnet) => true,
        (Network::Signet, Network::Testnet) => true,
        (Network::Testnet, Network::Signet) => true,
        (Network::Signet, Network::Signet) => true,
        (Network::Regtest, Network::Regtest) => true,
        _ => false,
    }
}
