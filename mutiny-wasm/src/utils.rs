#![allow(dead_code)]
use log::{debug, Level, Log, Metadata, Record};
use wasm_bindgen::prelude::*;
use web_sys::console;

pub fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function at least once during initialization, and then
    // we will get better error messages if our code ever panics.
    //
    // For more details see
    // https://github.com/rustwasm/console_error_panic_hook#readme
    console_error_panic_hook::set_once();
}

#[wasm_bindgen(start)]
pub async fn main_js() -> Result<(), JsValue> {
    init(Config::new(Level::Trace).message_on_new_line());
    debug!("Main function begins and ends");
    Ok(())
}

/// Specify what to be logged
pub struct Config {
    level: Level,
    module_prefix: Option<String>,
    message_location: MessageLocation,
}

/// Specify where the message will be logged.
pub enum MessageLocation {
    /// The message will be on the same line as other info (level, path...)
    SameLine,
    /// The message will be on its own line, a new after other info.
    NewLine,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            level: Level::Debug,
            module_prefix: None,
            message_location: MessageLocation::SameLine,
        }
    }
}

impl Config {
    /// Specify the maximum level you want to log
    pub fn new(level: Level) -> Self {
        Self {
            level,
            module_prefix: None,
            message_location: MessageLocation::SameLine,
        }
    }

    /// Configure the `target` of the logger. If specified, the logger
    /// only output for `log`s in module that its path starts with
    /// `module_prefix`. wasm-logger only supports single prefix. Only
    /// the last call to `module_prefix` has effect if you call it multiple times.
    pub fn module_prefix(mut self, module_prefix: &str) -> Self {
        self.module_prefix = Some(module_prefix.to_string());
        self
    }

    /// Put the message on a new line, separated from other information
    /// such as level, file path, line number.
    pub fn message_on_new_line(mut self) -> Self {
        self.message_location = MessageLocation::NewLine;
        self
    }
}

/// The logger
pub struct WasmLogger {
    pub config: Config,
}

impl Log for WasmLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        if let Some(ref prefix) = self.config.module_prefix {
            metadata.target().starts_with(prefix)
        } else {
            true
        }
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            let s = JsValue::from_str(&format!("{}", record.args()));

            match record.level() {
                Level::Trace => console::debug_1(&s),
                Level::Debug => console::log_1(&s),
                Level::Info => console::info_1(&s),
                Level::Warn => console::warn_1(&s),
                Level::Error => console::error_1(&s),
            }
        }
    }

    fn flush(&self) {}
}

/// Initialize the logger which the given config. If failed, it will log a message to the the browser console.
///
/// ## Examples
/// ```rust
/// wasm_logger::init(wasm_logger::Config::new(log::Level::Debug));
/// ```
/// or
/// ```rust
/// wasm_logger::init(wasm_logger::Config::with_prefix(log::Level::Debug, "some::module"));
/// ```
pub fn init(config: Config) {
    let max_level = config.level;
    let wl = WasmLogger { config };

    match log::set_boxed_logger(Box::new(wl)) {
        Ok(_) => log::set_max_level(max_level.to_level_filter()),
        Err(e) => console::error_1(&JsValue::from(e.to_string())),
    }
}

#[cfg(test)]
pub(crate) mod test {
    macro_rules! log {
        ( $( $t:tt )* ) => {
            web_sys::console::log_1(&format!( $( $t )* ).into());
        }
    }
    pub(crate) use log;
}
