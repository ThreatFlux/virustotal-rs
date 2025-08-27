//! Macros for reducing boilerplate code

/// Macro to generate `to_string` implementations for enums with simple string mappings
///
/// This macro creates a `to_string` method that returns `&'static str` for enum variants.
/// It reduces code duplication and complexity by generating the match statement automatically.
///
/// # Examples
///
/// ```rust
/// use virustotal_rs::impl_enum_to_string;
///
/// #[derive(Debug, Clone, Copy)]
/// enum Status {
///     Active,
///     Inactive,
/// }
///
/// impl_enum_to_string! {
///     Status {
///         Active => "active",
///         Inactive => "inactive",
///     }
/// }
///
/// assert_eq!(Status::Active.to_string(), "active");
/// ```
#[macro_export]
macro_rules! impl_enum_to_string {
    ($enum_type:ident {
        $($variant:ident => $string:expr),+ $(,)?
    }) => {
        impl $enum_type {
            /// Convert to API parameter string
            pub fn to_string(self) -> &'static str {
                match self {
                    $(Self::$variant => $string),+
                }
            }
        }
    };
}

/// Macro for implementing Display trait using the to_string method
/// This is useful when you want both to_string and Display implementations
#[macro_export]
macro_rules! impl_enum_display {
    ($enum_type:ident) => {
        impl std::fmt::Display for $enum_type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                let s = (*self).to_string();
                write!(f, "{}", s)
            }
        }
    };
}

/// Combined macro that implements both to_string and Display for an enum
#[macro_export]
macro_rules! impl_enum_string_conversion {
    ($enum_type:ident {
        $($variant:ident => $string:expr),+ $(,)?
    }) => {
        $crate::impl_enum_to_string! {
            $enum_type {
                $($variant => $string),+
            }
        }

        $crate::impl_enum_display!($enum_type);
    };
}

#[cfg(test)]
mod tests {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum TestVisibility {
        Public,
        Private,
    }

    impl_enum_to_string! {
        TestVisibility {
            Public => "public",
            Private => "private",
        }
    }

    impl_enum_display!(TestVisibility);

    #[test]
    fn test_to_string_macro() {
        assert_eq!(TestVisibility::Public.to_string(), "public");
        assert_eq!(TestVisibility::Private.to_string(), "private");
    }

    #[test]
    fn test_display_macro() {
        assert_eq!(TestVisibility::Public.to_string(), "public");
        assert_eq!(format!("{}", TestVisibility::Private), "private");
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum TestOrder {
        Asc,
        Desc,
    }

    impl_enum_string_conversion! {
        TestOrder {
            Asc => "asc",
            Desc => "desc",
        }
    }

    #[test]
    fn test_combined_macro() {
        assert_eq!(TestOrder::Asc.to_string(), "asc");
        assert_eq!(format!("{}", TestOrder::Desc), "desc");
    }
}
