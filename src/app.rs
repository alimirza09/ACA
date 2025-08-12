use crate::backend::*;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::sync::{Arc, Mutex};

#[derive(Deserialize, Serialize, Clone)]
pub struct Contact {
    pub onion_address: String,
    pub alias: String,
    pub is_online: bool,
    pub last_seen: Option<String>,
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
    message_cache: Arc<Mutex<std::collections::HashMap<String, Vec<(String, String, String)>>>>, // (sender, message, timestamp)
    #[serde(skip)]
    connection_status: ConnectionStatus,
}

#[derive(Debug, Clone)]
enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

impl Default for ConnectionStatus {
    fn default() -> Self {
        ConnectionStatus::Disconnected
    }
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
            connection_status: ConnectionStatus::default(),
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

        // Initialize message cache
        app.message_cache = Arc::new(Mutex::new(std::collections::HashMap::new()));
        app
    }

    fn validate_onion_address(&self, address: &str) -> bool {
        // Basic validation for v3 onion addresses
        address.len() == 62
            && address.ends_with(".onion")
            && address.chars().take(56).all(|c| c.is_ascii_alphanumeric())
    }

    fn load_messages_for_contact(&self, contact_address: &str) -> Vec<(String, String, String)> {
        // Check cache first
        if let Ok(cache) = self.message_cache.lock() {
            if let Some(messages) = cache.get(contact_address) {
                return messages.clone();
            }
        }

        // Load from file
        let (data_dir, _) = create_data_directories();
        let message_file = data_dir.join("messages").join(contact_address);

        let messages = match std::fs::read_to_string(&message_file) {
            Ok(buffer) => buffer
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(3, ": ").collect();
                    if parts.len() >= 3 {
                        let (timestamp, sender_type, message) = (parts[0], parts[1], parts[2]);
                        let sender = match sender_type {
                            "SENT" => "You".to_string(),
                            "RECEIVED" => self
                                .get_contact_alias(contact_address)
                                .unwrap_or_else(|| "Peer".to_string()),
                            _ => return None,
                        };
                        Some((sender, message.to_string(), timestamp.to_string()))
                    } else {
                        None
                    }
                })
                .collect(),
            Err(_) => Vec::new(),
        };

        // Cache the messages
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

    fn save_message(&self, contact_address: &str, message: &str, is_sent: bool) {
        let (data_dir, _) = create_data_directories();
        let message_file = data_dir.join("messages").join(contact_address);

        // Create directory if it doesn't exist
        if let Some(parent) = message_file.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let prefix = if is_sent { "SENT" } else { "RECEIVED" };
        let log_entry = format!("{}: {}: {}\n", timestamp, prefix, message);

        if let Err(e) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&message_file)
            .and_then(|mut file| {
                use std::io::Write;
                file.write_all(log_entry.as_bytes())
            })
        {
            eprintln!("Failed to save message: {}", e);
        }

        // Update cache
        if let Ok(mut cache) = self.message_cache.lock() {
            let entry = cache
                .entry(contact_address.to_string())
                .or_insert_with(Vec::new);
            let sender = if is_sent {
                "You".to_string()
            } else {
                self.get_contact_alias(contact_address)
                    .unwrap_or_else(|| "Peer".to_string())
            };
            entry.push((sender, message.to_string(), timestamp));
        }
    }

    fn send_message_to_selected_contact(&mut self, message: String) {
        if let Some(contact_idx) = self.selected_contact {
            if contact_idx < self.contacts.len() {
                let contact = self.contacts[contact_idx].clone();
                let message_clone = message.clone();
                let contact_address = contact.onion_address.clone();

                // Save message immediately
                self.save_message(&contact_address, &message, true);

                // Send message asynchronously
                tokio::spawn(async move {
                    match send_message_to_peer(&message_clone, &contact_address, 80).await {
                        Ok(_) => println!("Message sent to {}", contact_address),
                        Err(err) => eprintln!("Failed to send to {}: {:?}", contact_address, err),
                    }
                });
            }
        }
    }

    fn remove_contact(&mut self, index: usize) {
        if index < self.contacts.len() {
            self.contacts.remove(index);

            // Adjust selected contact index
            if let Some(selected) = self.selected_contact {
                if selected == index {
                    self.selected_contact = None;
                } else if selected > index {
                    self.selected_contact = Some(selected - 1);
                }
            }
        }
    }
}

impl eframe::App for AnotherChatApp {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel for connection status
        egui::TopBottomPanel::top("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let (color, text) = match &self.connection_status {
                    ConnectionStatus::Connected => {
                        (egui::Color32::GREEN, Cow::Borrowed("🟢 Connected"))
                    }
                    ConnectionStatus::Connecting => {
                        (egui::Color32::YELLOW, Cow::Borrowed("🟡 Connecting..."))
                    }
                    ConnectionStatus::Disconnected => {
                        (egui::Color32::GRAY, Cow::Borrowed("⚫ Disconnected"))
                    }
                    ConnectionStatus::Error(err) => {
                        (egui::Color32::RED, Cow::Owned(format!("🔴 Error: {}", err)))
                    }
                };
                ui.colored_label(color, text.as_ref());
            });
        });

        // Left panel for contacts
        egui::SidePanel::left("contacts")
            .resizable(true)
            .default_width(250.0)
            .show(ctx, |ui| {
                ui.heading("Contacts");

                ui.separator();

                // Contact list
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut to_remove = None;

                    for (index, contact) in self.contacts.iter().enumerate() {
                        ui.horizontal(|ui| {
                            let is_selected = self.selected_contact == Some(index);
                            let button_text = format!(
                                "{}\n{}",
                                contact.alias,
                                if contact.onion_address.len() > 20 {
                                    format!("{}...", &contact.onion_address[..20])
                                } else {
                                    contact.onion_address.clone()
                                }
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
                });

                ui.separator();

                // Add new contact section
                ui.collapsing("Add New Contact", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_onion_address)
                            .hint_text("example.onion")
                            .desired_width(f32::INFINITY),
                    );

                    ui.add(
                        egui::TextEdit::singleline(&mut self.new_alias)
                            .hint_text("Alias/Nickname")
                            .desired_width(f32::INFINITY),
                    );

                    let can_add = !self.new_onion_address.trim().is_empty()
                        && !self.new_alias.trim().is_empty()
                        && self.validate_onion_address(self.new_onion_address.trim());

                    ui.add_enabled_ui(can_add, |ui| {
                        if ui.button("Add Contact").clicked() {
                            let new_contact = Contact {
                                onion_address: self.new_onion_address.trim().to_string(),
                                alias: self.new_alias.trim().to_string(),
                                is_online: false,
                                last_seen: None,
                            };

                            self.contacts.push(new_contact);
                            self.new_onion_address.clear();
                            self.new_alias.clear();
                        }
                    });

                    if !self.new_onion_address.trim().is_empty()
                        && !self.validate_onion_address(self.new_onion_address.trim())
                    {
                        ui.colored_label(egui::Color32::RED, "Invalid onion address format");
                    }
                });
            });

        // Main chat panel
        egui::CentralPanel::default().show(ctx, |ui| {
            // Extract contact info before entering closures
            let contact_info = self
                .selected_contact
                .and_then(|idx| self.contacts.get(idx))
                .map(|contact| (contact.alias.clone(), contact.onion_address.clone()));

            // Pre-load messages if contact is selected
            let messages = contact_info
                .as_ref()
                .map(|(_, addr)| self.load_messages_for_contact(addr))
                .unwrap_or_default();

            if let Some((alias, address)) = contact_info {
                // Chat header
                ui.horizontal(|ui| {
                    ui.heading(&alias);
                    ui.label(format!("({})", address));
                });
                ui.separator();

                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    // Message input area
                    ui.horizontal(|ui| {
                        let response = ui.add_sized(
                            [ui.available_width() - 60.0, 25.0],
                            egui::TextEdit::singleline(&mut self.message_field)
                                .hint_text("Type a message..."),
                        );

                        // Handle Enter key
                        let enter_pressed = response.lost_focus()
                            && ui.input(|i| i.key_pressed(egui::Key::Enter))
                            && !self.message_field.trim().is_empty();

                        // Send button
                        let send_clicked =
                            ui.button("Send").clicked() && !self.message_field.trim().is_empty();

                        if enter_pressed || send_clicked {
                            let message = self.message_field.trim().to_string();
                            self.send_message_to_selected_contact(message);
                            self.message_field.clear();
                            response.request_focus();
                        }
                    });

                    ui.separator();

                    // Messages area
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .max_height(ui.available_height())
                        .show(ui, |ui| {
                            if messages.is_empty() {
                                ui.centered_and_justified(|ui| {
                                    ui.label("No messages yet. Start a conversation!");
                                });
                            } else {
                                for (sender, message, timestamp) in messages {
                                    let is_own_message = sender == "You";

                                    ui.horizontal(|ui| {
                                        if is_own_message {
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::TOP),
                                                |ui| {
                                                    ui.label(
                                                        egui::RichText::new(&message)
                                                            .background_color(
                                                                egui::Color32::from_rgb(
                                                                    0, 150, 255,
                                                                ),
                                                            )
                                                            .color(egui::Color32::WHITE),
                                                    );
                                                    ui.label(
                                                        egui::RichText::new(&format!(
                                                            "{} - {}",
                                                            sender, timestamp
                                                        ))
                                                        .small()
                                                        .color(egui::Color32::GRAY),
                                                    );
                                                },
                                            );
                                        } else {
                                            ui.label(
                                                egui::RichText::new(&format!(
                                                    "{} - {}",
                                                    sender, timestamp
                                                ))
                                                .small()
                                                .color(egui::Color32::GRAY),
                                            );
                                            ui.label(&message);
                                        }
                                    });
                                    ui.add_space(8.0); // Add spacing between messages
                                }
                            }
                        });
                });
            } else {
                ui.centered_and_justified(|ui| {
                    ui.label("Select a contact to start chatting");
                });
            }
        });

        // Request repaint for real-time updates
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}
