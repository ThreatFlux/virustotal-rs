#[cfg(test)]
mod unit_tests {
    use crate::files::*;
    use crate::objects::ObjectOperations;

    #[test]
    fn test_file_collection_name() {
        assert_eq!(File::collection_name(), "files");
    }

    #[test]
    fn test_file_url() {
        assert_eq!(
            File::object_url("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"),
            "files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        );
    }

    #[test]
    fn test_file_relationships_url() {
        assert_eq!(
            File::relationships_url("hash123", "bundled_files"),
            "files/hash123/relationships/bundled_files"
        );
    }
}
