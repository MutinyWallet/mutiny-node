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
    init(
        Config::new(Level::Trace).message_on_new_line(),
        Style::none(),
    );
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

/// The log styles
pub struct Style {
    pub lvl_trace: String,
    pub lvl_debug: String,
    pub lvl_info: String,
    pub lvl_warn: String,
    pub lvl_error: String,
    pub tgt: String,
    pub args: String,
}

impl Style {
    pub fn new() -> Style {
        let base = String::from("color: white; padding: 0 3px; background:");
        Style {
            lvl_trace: format!("{} gray;", base),
            lvl_debug: format!("{} blue;", base),
            lvl_info: format!("{} green;", base),
            lvl_warn: format!("{} orange;", base),
            lvl_error: format!("{} darkred;", base),
            tgt: String::from("font-weight: bold; color: inherit"),
            args: String::from("background: inherit; color: inherit"),
        }
    }

    pub fn none() -> Style {
        Style {
            lvl_trace: String::new(),
            lvl_debug: String::new(),
            lvl_info: String::new(),
            lvl_warn: String::new(),
            lvl_error: String::new(),
            tgt: String::new(),
            args: String::new(),
        }
    }
}

/// The logger
pub struct WasmLogger {
    pub config: Config,
    pub style: Style,
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
            let style = &self.style;
            let s = format!("{}", record.args());
            let s = JsValue::from_str(&s);
            let tgt_style = JsValue::from_str(&style.tgt);
            let args_style = JsValue::from_str(&style.args);

            match record.level() {
                Level::Trace => console::debug_4(
                    &s,
                    &JsValue::from(&style.lvl_trace),
                    &tgt_style,
                    &args_style,
                ),
                Level::Debug => console::log_4(
                    &s,
                    &JsValue::from(&style.lvl_debug),
                    &tgt_style,
                    &args_style,
                ),
                Level::Info => {
                    console::info_4(&s, &JsValue::from(&style.lvl_info), &tgt_style, &args_style)
                }
                Level::Warn => {
                    console::warn_4(&s, &JsValue::from(&style.lvl_warn), &tgt_style, &args_style)
                }
                Level::Error => console::error_4(
                    &s,
                    &JsValue::from(&style.lvl_error),
                    &tgt_style,
                    &args_style,
                ),
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
pub fn init(config: Config, style: Style) {
    let max_level = config.level;
    let wl = WasmLogger { config, style };

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
