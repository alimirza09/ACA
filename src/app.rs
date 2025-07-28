/// We derive Deserialize/Serialize so we can persist app state on shutdown.
///
use crate::backend;
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
#[allow(non_snake_case)]

pub struct AnotherChatApp {
    // Example stuff:
    label: String,
}

impl Default for AnotherChatApp {
    fn default() -> Self {
        Self {
            label: "Another Chat App".to_owned(),
        }
    }
}

impl AnotherChatApp {
    /// Called once before the first frame.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        }
    }
}

impl eframe::App for AnotherChatApp {
    /// Called by the framework to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Put your widgets into a `SidePanel`, `TopBottomPanel`, `CentralPanel`, `Window` or `Area`.
        // For inspiration and more examples, go to https://emilk.github.io/egui

        egui::SidePanel::left("contacts").show(ctx, |ui| {
            ui.label("Contacts");
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.horizontal(|ui| {
                    let message =
                        ui.add(egui::TextEdit::singleline(&mut self.label).hint_text("message"));
                    if message.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        backend::handle_message(&self.label);

                        self.label.clear();
                    }
                });
            });

            ui.separator();
        });
    }
}
