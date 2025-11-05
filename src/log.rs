use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

// macro that only prints when VERBOSE is true
#[macro_export]
macro_rules! vprintln {
    ($($arg:tt)*) => {
        if $crate::log::is_verbose() {
            println!($($arg)*);
        }
    };
}
