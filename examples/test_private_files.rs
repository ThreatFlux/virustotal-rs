mod common;
mod private_files_modules;

#[tokio::main]
async fn main() -> common::ExampleResult<()> {
    private_files_modules::run_private_files_test().await
}