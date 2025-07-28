#![warn(clippy::all, rust_2018_idioms)]
#![allow(clippy::nonstandard_macro_braces)]
#[allow(non_snake_case)]
pub mod app;
pub mod backend;
pub use app::AnotherChatApp;
