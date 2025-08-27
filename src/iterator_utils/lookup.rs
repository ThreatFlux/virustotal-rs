//! Lookup table utilities for efficient enum string conversions

use std::collections::HashMap;

/// A lookup table for converting enums to strings
pub struct LookupTable<K, V> {
    map: HashMap<K, V>,
}

impl<K, V> LookupTable<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    /// Create a new lookup table from an iterator of key-value pairs
    pub fn from_iterator<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
    {
        Self {
            map: iter.into_iter().collect(),
        }
    }

    /// Get a value by key, returning a clone
    pub fn get(&self, key: &K) -> Option<V> {
        self.map.get(key).cloned()
    }

    /// Get a value by key, returning a reference
    pub fn get_ref(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    /// Check if the table contains a key
    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Get the number of entries in the table
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Macro to create a static lookup table for enum to string conversions
#[macro_export]
macro_rules! create_lookup_table {
    ($(#[$meta:meta])* $vis:vis static $name:ident : LookupTable<$key:ty, $value:ty> = {
        $($variant:expr => $string:expr),+ $(,)?
    }) => {
        $(#[$meta])*
        $vis static $name: std::sync::LazyLock<$crate::iterator_utils::lookup::LookupTable<$key, $value>> =
            std::sync::LazyLock::new(|| {
                $crate::iterator_utils::lookup::LookupTable::from_iterator([
                    $(($variant, $string)),+
                ])
            });
    };
}

/// Trait for types that can be converted to strings using lookup tables
pub trait StringLookup {
    fn to_string_lookup(&self) -> &'static str;
}

/// Create a lookup table for a specific enum type
pub fn create_enum_lookup<E, S>(pairs: &[(E, S)]) -> LookupTable<E, S>
where
    E: Clone + Eq + std::hash::Hash,
    S: Clone,
{
    LookupTable::from_iterator(pairs.iter().cloned())
}

/// Builder for creating lookup tables with fluent API
pub struct LookupTableBuilder<K, V> {
    pairs: Vec<(K, V)>,
}

impl<K, V> Default for LookupTableBuilder<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LookupTableBuilder<K, V>
where
    K: Eq + std::hash::Hash + Clone,
    V: Clone,
{
    /// Create a new builder
    pub fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    /// Add a key-value pair to the builder
    pub fn add(mut self, key: K, value: V) -> Self {
        self.pairs.push((key, value));
        self
    }

    /// Build the lookup table
    pub fn build(self) -> LookupTable<K, V> {
        LookupTable::from_iterator(self.pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    enum TestEnum {
        First,
        Second,
        Third,
    }

    #[test]
    fn test_lookup_table_basic() {
        let table = LookupTable::from_iterator([
            (TestEnum::First, "first"),
            (TestEnum::Second, "second"),
            (TestEnum::Third, "third"),
        ]);

        assert_eq!(table.get(&TestEnum::First), Some("first"));
        assert_eq!(table.get(&TestEnum::Second), Some("second"));
        assert_eq!(table.get(&TestEnum::Third), Some("third"));
        assert_eq!(table.len(), 3);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_lookup_table_builder() {
        let table = LookupTableBuilder::new()
            .add(TestEnum::First, "first")
            .add(TestEnum::Second, "second")
            .build();

        assert_eq!(table.get(&TestEnum::First), Some("first"));
        assert_eq!(table.get(&TestEnum::Second), Some("second"));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_create_enum_lookup() {
        let pairs = [(TestEnum::First, "first"), (TestEnum::Second, "second")];
        let table = create_enum_lookup(&pairs);

        assert_eq!(table.get(&TestEnum::First), Some("first"));
        assert_eq!(table.get(&TestEnum::Second), Some("second"));
    }

    // Test the macro (this would typically be in the crate using it)
    create_lookup_table! {
        static TEST_LOOKUP: LookupTable<TestEnum, &'static str> = {
            TestEnum::First => "first",
            TestEnum::Second => "second",
            TestEnum::Third => "third",
        }
    }

    #[test]
    fn test_lookup_macro() {
        assert_eq!(TEST_LOOKUP.get(&TestEnum::First), Some("first"));
        assert_eq!(TEST_LOOKUP.get(&TestEnum::Second), Some("second"));
        assert_eq!(TEST_LOOKUP.get(&TestEnum::Third), Some("third"));
    }
}
