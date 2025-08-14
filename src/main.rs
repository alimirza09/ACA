#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release

use another_chat_app::backend::setup_tor_and_http;
use anyhow::Result;
use tokio;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    another_chat_app::crypto::init_crypto();

    let port = 8000;
    tokio::spawn(async move {
        let _ = another_chat_app::backend::crypto_setup();
        let _ = setup_tor_and_http(port).await;
    });
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_min_inner_size([300.0, 220.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(
                    &include_bytes!("../assets/iconFinal256.png")[..],
                )
                .expect("Failed to load icon"),
            ),
        ..Default::default()
    };

    let _app_result = eframe::run_native(
        "Another Chat App",
        native_options,
        Box::new(|cc| Ok(Box::new(another_chat_app::AnotherChatApp::new(cc)))),
    );

    Ok(())
}
