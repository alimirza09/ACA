use crate::backend::*;
use egui::Color32;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct Contact {
    pub onion_address: String,
    pub alias: String,
    pub pk: String,
}

#[derive(Deserialize, Serialize)]
#[serde(default)]
pub struct AnotherChatApp {
    message_field: String,
    new_onion_address: String,
    new_alias: String,
    contacts: Vec<Contact>,
    selected_contact: Option<usize>,
    pending_handshake: Option<(String, String)>,
    show_alias_prompt: bool,
    alias_input: String,
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
            pending_handshake: None,
            show_alias_prompt: false,
            alias_input: String::new(),
            message_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

impl AnotherChatApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self {
            message_field: String::new(),
            new_onion_address: String::new(),
            new_alias: String::new(),
            contacts: load_contacts_from_json(),
            selected_contact: None,
            pending_handshake: None,
            show_alias_prompt: false,
            alias_input: String::new(),
            message_cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        };

        app
    }

    fn validate_onion_address(&self, address: &str) -> bool {
        address.len() == 62
            && address.ends_with(".onion")
            && address.chars().take(56).all(|c| c.is_ascii_alphanumeric())
    }

    fn check_for_handshakes(&mut self) {
        if let Ok(handshake_data) = check_for_pending_handshake() {
            if let Some((onion_address, pk)) = handshake_data {
                if let Some(contact) = self
                    .contacts
                    .iter_mut()
                    .find(|c| c.onion_address == onion_address)
                {
                    contact.pk = pk;
                    self.save_contacts();
                } else {
                    self.pending_handshake = Some((onion_address, pk));
                    self.show_alias_prompt = true;
                    self.alias_input.clear();
                }
            }
        }
    }

    fn update_contact_pk(&mut self, onion_address: &str, pk: String) {
        if let Some(contact) = self
            .contacts
            .iter_mut()
            .find(|c| c.onion_address == onion_address)
        {
            contact.pk = pk;
            self.save_contacts();
        }
    }

    fn refresh_contacts(&mut self) {
        let all_contacts = load_contacts_from_json();
        for contact in all_contacts {
            let already_exists = self
                .contacts
                .iter()
                .any(|c| c.onion_address == contact.onion_address);
            if !already_exists {
                self.contacts.push(contact);
            }
        }
    }

    fn save_contacts(&self) {
        save_contacts_to_json(&self.contacts);
    }

    fn add_contact(&mut self, onion_address: String, alias: String) {
        let new_contact = Contact {
            onion_address,
            alias,
            pk: String::new(),
        };
        self.contacts.push(new_contact);
        self.save_contacts();
    }

    fn remove_contact(&mut self, index: usize) {
        if index < self.contacts.len() {
            self.contacts.remove(index);
            self.save_contacts();
            if let Some(selected) = self.selected_contact {
                if selected == index {
                    self.selected_contact = None;
                } else if selected > index {
                    self.selected_contact = Some(selected - 1);
                }
            }
        }
    }

    fn load_messages_for_contact(&self, contact_address: &str) -> Vec<(String, String)> {
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

    fn refresh_messages_for_contact(&self, contact_address: &str) {
        if let Ok(mut cache) = self.message_cache.lock() {
            cache.remove(contact_address);
        }
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

                self.refresh_messages_for_contact(&contact_address);

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
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.check_for_handshakes();
        self.refresh_contacts();

        if self.show_alias_prompt {
            egui::Window::new("New Contact")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                .show(ctx, |ui| {
                    if let Some((onion_address, _)) = &self.pending_handshake {
                        ui.label(format!(
                            "Someone wants to connect: {}",
                            if onion_address.len() > 20 {
                                format!("{}...", &onion_address[..20])
                            } else {
                                onion_address.clone()
                            }
                        ));
                        ui.separator();

                        ui.label("Enter an alias for this contact:");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.alias_input).hint_text("Alias"),
                        );

                        ui.horizontal(|ui| {
                            if ui.button("Accept").clicked() && !self.alias_input.trim().is_empty()
                            {
                                if let Some((onion_address, pk)) = self.pending_handshake.take() {
                                    let new_contact = Contact {
                                        onion_address,
                                        alias: self.alias_input.trim().to_string(),
                                        pk,
                                    };
                                    self.contacts.push(new_contact);
                                    self.save_contacts();
                                }
                                self.show_alias_prompt = false;
                                self.alias_input.clear();
                            }

                            if ui.button("Reject").clicked() {
                                self.pending_handshake = None;
                                self.show_alias_prompt = false;
                                self.alias_input.clear();
                            }
                        });
                    }
                });
        }

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

                    let encryption_status = if contact.pk.is_empty() {
                        "🔓"
                    } else {
                        "🔒"
                    };

                    let button_text = format!(
                        "{} {}\n{}",
                        encryption_status, contact.alias, truncated_address
                    );

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
                self.remove_contact(index);
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
                        self.add_contact(
                            self.new_onion_address.trim().to_string(),
                            self.new_alias.trim().to_string(),
                        );
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
                                    let (bg_color, align, text_color) = if sender == "You" {
                                        (
                                            Color32::from_rgb(0, 192, 249),
                                            egui::Align::RIGHT,
                                            Color32::BLACK,
                                        )
                                    } else {
                                        (
                                            Color32::from_rgb(0, 131, 185),
                                            egui::Align::LEFT,
                                            Color32::WHITE,
                                        )
                                    };

                                    let padding = egui::vec2(8.0, 4.0);
                                    let rounding = 8.0;

                                    ui.with_layout(egui::Layout::bottom_up(align), |ui| {
                                        let font_id = egui::TextStyle::Body.resolve(ui.style());
                                        let max_text_width = ui.available_width() * 0.75;
                                        let galley = ui.fonts(|fonts| {
                                            fonts.layout(
                                                message.clone(),
                                                font_id.clone(),
                                                text_color,
                                                max_text_width,
                                            )
                                        });

                                        let size = galley.size() + 2.0 * padding;

                                        let (rect, _) =
                                            ui.allocate_exact_size(size, egui::Sense::hover());
                                        ui.painter().rect_filled(rect, rounding, bg_color);
                                        ui.painter().galley(
                                            rect.min + padding,
                                            galley,
                                            Color32::WHITE,
                                        );
                                    });

                                    ui.add_space(5.0);
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
