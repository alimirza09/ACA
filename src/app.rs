use crate::backend::*;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Serialize, Clone)]
pub struct Contact {
    pub onion_address: String,
    pub alias: String,
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct AnotherChatApp {
    message_field: String,
    new_onion_address: String,
    new_alias: String,
    contacts: Vec<Contact>,
    selected_contact: Option<usize>,
    #[serde(skip)]
    message_cache: Arc<Mutex<std::collections::HashMap<String, Vec<(String, String)>>>>,
}

impl Default for AnotherChatApp {
    fn default() -> Self {
        Self {
            message_field: String::new(),
            new_onion_address: String::new(),
            new_alias: String::new(),
            contacts: Vec::new(),
            selected_contact: None,
            message_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl AnotherChatApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app: Self = if let Some(storage) = cc.storage {
            eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default()
        } else {
            Default::default()
        };

        app.message_cache = Arc::new(Mutex::new(std::collections::HashMap::new()));
        app
    }

    fn validate_onion_address(&self, address: &str) -> bool {
        address.len() == 62
            && address.ends_with(".onion")
            && address.chars().take(56).all(|c| c.is_ascii_alphanumeric())
    }

    fn load_messages_for_contact(&self, contact_address: &str) -> Vec<(String, String)> {
        if let Ok(mut cache) = self.message_cache.lock() {
            cache.remove(contact_address);
        }
        if let Ok(cache) = self.message_cache.lock() {
            if let Some(messages) = cache.get(contact_address) {
                return messages.clone();
            }
        }

        let (data_dir, _) = create_data_directories();
        let message_file = data_dir.join("messages").join(contact_address);

        let messages = match std::fs::read_to_string(&message_file) {
            Ok(buffer) => buffer
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(2, ": ").collect();
                    if parts.len() == 2 {
                        let (sender_type, message) = (parts[0], parts[1]);
                        let sender = match sender_type {
                            "SENT" => "You".to_string(),
                            "RECEIVED" => self
                                .get_contact_alias(contact_address)
                                .unwrap_or_else(|| "Peer".to_string()),
                            _ => return None,
                        };
                        Some((sender, message.to_string()))
                    } else {
                        None
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        if let Ok(mut cache) = self.message_cache.lock() {
            cache.insert(contact_address.to_string(), messages.clone());
        }

        messages
    }

    fn get_contact_alias(&self, onion_address: &str) -> Option<String> {
        self.contacts
            .iter()
            .find(|c| c.onion_address == onion_address)
            .map(|c| c.alias.clone())
    }

    fn send_message_to_selected_contact(&mut self, message: String) {
        if let Some(contact_idx) = self.selected_contact {
            if let Some(contact) = self.contacts.get(contact_idx) {
                let contact_address = contact.onion_address.clone();

                tokio::spawn(async move {
                    match send_message_to_peer(&message, &contact_address, 80).await {
                        Ok(_) => println!("Message sent to {}", contact_address),
                        Err(err) => eprintln!("Failed to send to {}: {:?}", contact_address, err),
                    }
                });
            }
        }
    }
}

impl eframe::App for AnotherChatApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::SidePanel::left("contacts").show(ctx, |ui| {
            ui.heading("Contacts");

            let mut to_remove = None;

            for (index, contact) in self.contacts.iter().enumerate() {
                let is_selected = self.selected_contact == Some(index);

                ui.horizontal(|ui| {
                    let truncated_address = if contact.onion_address.len() > 16 {
                        format!("{}...", &contact.onion_address[..16])
                    } else {
                        contact.onion_address.clone()
                    };

                    let button_text = format!("{}\n{}", contact.alias, truncated_address);

                    if ui.selectable_label(is_selected, button_text).clicked() {
                        self.selected_contact = Some(index);
                    }

                    if ui.small_button("🗑").clicked() {
                        to_remove = Some(index);
                    }
                });
                ui.separator();
            }

            if let Some(index) = to_remove {
                self.contacts.remove(index);
                if let Some(selected) = self.selected_contact {
                    if selected == index {
                        self.selected_contact = None;
                    } else if selected > index {
                        self.selected_contact = Some(selected - 1);
                    }
                }
            }

            ui.collapsing("Add New Contact", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_onion_address)
                        .hint_text("Onion address"),
                );

                ui.add(egui::TextEdit::singleline(&mut self.new_alias).hint_text("Alias"));

                let can_add = !self.new_onion_address.trim().is_empty()
                    && !self.new_alias.trim().is_empty()
                    && self.validate_onion_address(self.new_onion_address.trim());

                ui.add_enabled_ui(can_add, |ui| {
                    if ui.button("Add Contact").clicked() {
                        let new_contact = Contact {
                            onion_address: self.new_onion_address.trim().to_string(),
                            alias: self.new_alias.trim().to_string(),
                        };

                        self.contacts.push(new_contact);
                        self.new_onion_address.clear();
                        self.new_alias.clear();
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(contact_idx) = self.selected_contact {
                let contact_address = self
                    .contacts
                    .get(contact_idx)
                    .map(|c| c.onion_address.clone());

                if let Some(contact_address) = contact_address {
                    ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                        ui.horizontal(|ui| {
                            let response = ui.add_sized(
                                [ui.available_width() - 60.0, 20.0],
                                egui::TextEdit::singleline(&mut self.message_field)
                                    .hint_text("Message"),
                            );

                            if response.lost_focus()
                                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                && !self.message_field.trim().is_empty()
                            {
                                let message = self.message_field.trim().to_string();
                                self.send_message_to_selected_contact(message);
                                self.message_field.clear();
                            }

                            if ui.button("Send").clicked() && !self.message_field.trim().is_empty()
                            {
                                let message = self.message_field.trim().to_string();
                                self.send_message_to_selected_contact(message);
                                self.message_field.clear();
                            }
                        });

                        egui::ScrollArea::vertical()
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                let mut messages = self.load_messages_for_contact(&contact_address);
                                messages.reverse();
                                for (sender, message) in messages {
                                    ui.label(format!("{}: {}", sender, message));
                                }
                            });

                        ui.separator();
                    });
                }
            } else {
                ui.label("Select a contact to start chatting");
            }
        });
    }
}
