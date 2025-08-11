use crate::backend::*;
use serde::{Deserialize, Serialize};
use std::io::prelude::*;

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct AnotherChatApp {
    message_field: String,
    #[serde(skip)]
    contacts: Vec<Contact>,
}

struct Contact {
    onion_address: String,
    alias: String,
}

impl Default for AnotherChatApp {
    fn default() -> Self {
        Self {
            message_field: String::new(),
            contacts: Vec::new(),
        }
    }
}

impl AnotherChatApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        }
    }
}

impl eframe::App for AnotherChatApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);

        // let mut onion_address_whatever = String::new();
        //
        // let mut alias_text = String::new();
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("contacts").show(ctx, |ui| {
            ui.heading("Contacts");
            for contact in &self.contacts {
                ui.label(format!("{} ({})", contact.alias, contact.onion_address));
            }
            // ui.collapsing("New", |ui| {
            //     let onion_address = ui.add(
            //         egui::TextEdit::singleline(&mut onion_address_whatever)
            //             .hint_text("Onion address"),
            //     );
            //     let alias = ui.add(egui::TextEdit::singleline(&mut alias_text).hint_text("Alias"));
            //     if onion_address.lost_focus()
            //         && ui.input(|i| i.key_pressed(egui::Key::Enter))
            //         && !onion_address_whatever.trim().is_empty()
            //         && !alias_text.trim().is_empty()
            //     {
            //         let onion_address = onion_address_whatever.trim().to_string();
            //         let alias_name = alias_text.trim().to_string();
            //         self.contacts.push(Contact {
            //             onion_address: onion_address,
            //             alias: alias_name,
            //         });
            //
            //         alias_text.clear();
            //         onion_address_whatever.clear();
            //     }
            // });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                ui.horizontal(|ui| {
                    let response = ui.add(
                        egui::TextEdit::singleline(&mut self.message_field).hint_text("message"),
                    );

                    if response.lost_focus()
                        && ui.input(|i| i.key_pressed(egui::Key::Enter))
                        && !self.message_field.trim().is_empty()
                    {
                        let message = self.message_field.trim().to_string();

                        let to_send = message.clone();
                        tokio::spawn(async move {
                            match send_message_to_peer(&to_send, ONION_PEER, 80).await {
                                Ok(_) => println!("Message sent!"),
                                Err(err) => eprintln!("Failed to send: {:?}", err),
                            }
                        });

                        self.message_field.clear();
                    }
                });

                ui.separator();

                let (data_dir, _) = create_data_directories();
                let message_file = data_dir.join("messages").join(ONION_PEER);
                let mut file = std::fs::File::open(message_file).unwrap();
                let mut buffer = String::new();
                file.read_to_string(&mut buffer).unwrap();

                let lines: Vec<&str> = buffer.lines().collect();
                for line in lines.iter().rev() {
                    let sender;
                    let message;
                    if line.starts_with("SENT: ") {
                        sender = "You";
                        message = line.strip_prefix("SENT: ").unwrap();
                    } else {
                        sender = "Peer";
                        message = line.strip_prefix("RECEIVED: ").unwrap();
                    };
                    ui.label(format!("{}: {}", sender, message));
                }
            });
        });
    }
}
