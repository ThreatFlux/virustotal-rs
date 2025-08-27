//! Error handling macros for reducing boilerplate

/// Error handling macros for reducing boilerplate
#[macro_export]
macro_rules! bail_if {
    ($condition:expr, $error:expr) => {
        if $condition {
            return Err($error);
        }
    };
}

/// Ensure condition is true or return error
#[macro_export]
macro_rules! ensure {
    ($condition:expr, $error:expr) => {
        if !$condition {
            return Err($error);
        }
    };
}

/// Add context to a result
#[macro_export]
macro_rules! context {
    ($result:expr, $message:expr) => {
        $result.map_err(|e| $crate::Error::unknown(format!("{}: {}", $message, e)))
    };
}

/// Map error with context
#[macro_export]
macro_rules! map_err_context {
    ($result:expr, $message:expr) => {
        $result.map_err(|e| $crate::Error::unknown(format!("{}: {}", $message, e)))
    };
}
