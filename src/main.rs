#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    let mut file = File::create("messages.csv")?;
    file.write_all("message, userid \n".as_bytes())?;
    drop(file);

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 300.0])
            .with_min_inner_size([300.0, 220.0])
            .with_icon(
                eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon-256.png")[..])
                    .expect("Failed to load icon"),
            ),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Another Chat App",
        native_options,
        Box::new(|cc| Ok(Box::new(another_chat_app::AnotherChatApp::new(cc)))),
    );
    Ok(())
}
