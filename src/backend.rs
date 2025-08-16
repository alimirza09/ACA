use crate::app::Contact;
use crate::crypto::{
    decrypt_message, encode_public_key, encrypt_message, generate_and_store_keypair, load_keypair,
    parse_public_key,
};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};
use tokio_socks::tcp::socks5::*;

pub async fn get_message_count(sender: &str) -> usize {
    let message_file = message_file(sender);

    match tokio::fs::read_to_string(message_file).await {
        Ok(content) => content.lines().count(),
        Err(_) => 0,
    }
}

async fn handshake(onion_peer: &str) -> Result<()> {
    let (pk, _) = crypto_setup();
    let pk_b64 = encode_public_key(&pk);

    if check_if_first_contact(onion_peer) {
        let mut stream = connect_to_peer(onion_peer, 8000).await?;
        let handshake = format!("HANDSHAKE: {}:{}", onion_peer, pk_b64);
        stream.write_all(handshake.as_bytes()).await?
    }
    Ok(())
}

pub async fn add_new_contact(contact: Contact) -> Result<()> {
    let (data_dir, _) = create_data_directories();
    let contacts_file = data_dir.join("contacts").join("contacts.json");

    let mut contacts: Vec<Contact> = if contacts_file.exists() {
        let data = tokio::fs::read(&contacts_file).await?;
        serde_json::from_slice(&data).unwrap_or_default()
    } else {
        Vec::new()
    };

    contacts.push(contact);

    let smth = serde_json::to_string_pretty(&contacts)?;
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(contacts_file)
        .await?;
    file.write_all(smth.as_bytes()).await?;

    Ok(())
}
pub fn load_contacts_from_json() -> Vec<Contact> {
    let (data_dir, _) = create_data_directories();
    let contacts_file = data_dir.join("contacts.json");

    match std::fs::read_to_string(contacts_file) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn store_pending_handshake(onion_address: &str, pk: &str) -> Result<()> {
    let (data_dir, _) = create_data_directories();
    let handshake_file = data_dir.join("pending_handshake.txt");

    let handshake_data = format!("{}|{}", onion_address, pk);
    std::fs::write(handshake_file, handshake_data)?;

    Ok(())
}

pub fn check_for_pending_handshake() -> Result<Option<(String, String)>> {
    let (data_dir, _) = create_data_directories();
    let handshake_file = data_dir.join("pending_handshake.txt");

    if !handshake_file.exists() {
        return Ok(None);
    }

    let content = std::fs::read_to_string(&handshake_file)?;
    std::fs::remove_file(&handshake_file)?;
    if let Some((onion_address, pk)) = content.trim().split_once('|') {
        Ok(Some((onion_address.to_string(), pk.to_string())))
    } else {
        Ok(None)
    }
}

pub fn add_contact_to_json(onion_address: &str, alias: &str) {
    let mut contacts = load_contacts_from_json();

    if contacts.iter().any(|c| c.onion_address == onion_address) {
        return;
    }

    contacts.push(Contact {
        onion_address: onion_address.to_string(),
        alias: alias.to_string(),
        pk: String::new(),
    });

    save_contacts_to_json(&contacts);
    println!("Added contact: {} ({})", alias, onion_address);
}

pub fn update_contact_pk(onion_address: &str, pk: &str) -> Result<()> {
    let mut contacts = load_contacts_from_json();

    if let Some(contact) = contacts
        .iter_mut()
        .find(|c| c.onion_address == onion_address)
    {
        contact.pk = pk.to_string();
        save_contacts_to_json(&contacts);
        println!("Updated public key for contact: {}", onion_address);
    }

    Ok(())
}

async fn handle_handshake(request: &str) -> Result<()> {
    if let Some((onion_peer, pk_peer_b64)) = decode_handshake(request) {
        let contacts = load_contacts_from_json();
        if let Some(_existing_contact) = contacts.iter().find(|c| c.onion_address == onion_peer) {
            update_contact_pk(onion_peer, pk_peer_b64)?;
        } else {
            store_pending_handshake(onion_peer, pk_peer_b64)?;
        }
    }
    Ok(())
}

pub fn save_contacts_to_json(contacts: &[Contact]) {
    let (data_dir, _) = create_data_directories();
    let contacts_file = data_dir.join("contacts.json");

    if let Ok(json) = serde_json::to_string_pretty(contacts) {
        if let Err(e) = std::fs::write(contacts_file, json) {
            eprintln!("Failed to save contacts: {}", e);
        }
    }
}

pub fn crypto_setup() -> (PublicKey, SecretKey) {
    let (data_dir, _) = create_data_directories();
    if check_if_first_time() {
        let (pk, sk) = generate_and_store_keypair(&data_dir);
        (pk, sk)
    } else {
        load_keypair(&data_dir)
    }
}
fn decode_handshake(request: &str) -> Option<(&str, &str)> {
    let request = request.trim().strip_prefix("HANDSHAKE:")?;
    let parts: Vec<&str> = request.splitn(2, ": ").collect();
    let onion_peer = parts[0];
    let pk_peer_b64 = parts[1];
    Some((onion_peer, pk_peer_b64))
}

pub fn message_file(onion_peer: &str) -> std::path::PathBuf {
    let (data_dir, _) = create_data_directories();
    let file_path = data_dir.join("messages").join(onion_peer);
    if !file_path.exists() {
        std::fs::File::create(file_path.clone()).unwrap();
    }
    file_path
}
pub fn create_file(file: &str, create: bool) -> Result<std::path::PathBuf> {
    let (data_dir, _) = create_data_directories();
    let file_path = data_dir.join(file);
    if file_path.exists() && create {
        std::fs::File::create(file_path.clone())?;
    };

    Ok(file_path)
}

pub fn remove_file(file: std::path::PathBuf) -> Result<()> {
    std::fs::remove_file(file)?;
    Ok(())
}

fn check_if_first_contact(onion_peer: &str) -> bool {
    let message_file = message_file(onion_peer);
    !message_file.exists()
}

async fn connect_to_peer(onion_peer: &str, port: u16) -> Result<TcpStream> {
    let stream =
        Socks5Stream::connect("127.0.0.1:9050", format!("{}:{}", onion_peer, port)).await?;
    Ok(stream.into_inner())
}

fn determine_onion_address() -> Result<String> {
    let (_, tor_data_dir) = create_data_directories();
    let hostname_file = tor_data_dir.join("hidden_service").join("hostname");
    let onion_address = std::fs::read_to_string(hostname_file)?;
    Ok(onion_address.trim().to_string())
}

async fn handle_outgoing_message(message: &str, receiver: &str) -> Option<()> {
    let message_file = message_file(receiver);
    let message_body_with_newline = String::from("SENT: ") + message + "\n";

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(message_file)
        .await
        .ok()?;

    file.write_all(message_body_with_newline.as_bytes())
        .await
        .ok()?;
    Some(())
}

fn decode_incoming_message(message: &str) -> Option<(String, &str)> {
    let message = message.trim().strip_prefix("MSG:")?;
    let pos_of_from = message.rfind(" FROM:")?;
    let message_body = &message[0..pos_of_from];
    let sender = &message[pos_of_from + 6..];
    let message_body_with_newline = String::from("RECEIVED: ") + message_body + "\n";
    Some((message_body_with_newline, sender))
}

pub fn check_if_first_time() -> bool {
    let data_dir = dirs::data_dir().unwrap().join("another-chat-app");
    !data_dir.exists()
}

pub fn create_data_directories() -> (std::path::PathBuf, std::path::PathBuf) {
    let data_dir = dirs::data_dir().unwrap().join("another-chat-app");
    let tor_data_dir = data_dir.join("tor");

    if check_if_first_time() {
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::create_dir(&tor_data_dir).unwrap();
        std::fs::create_dir(data_dir.join("messages")).unwrap();
        std::fs::create_dir(data_dir.join("contacts")).unwrap();
    }

    (data_dir, tor_data_dir)
}

async fn generate_tor_config(hidden_service_port: u16) -> Result<()> {
    let (_, tor_data_dir) = create_data_directories();
    let torrc_path = format!("/tmp/torrc-{}", std::process::id());
    let content = format!(
        "# Tor configuration for hidden service
DataDirectory {}
SocksPort 9050
ControlPort 9051
CookieAuthentication 1

HiddenServiceDir {}
HiddenServicePort 80 127.0.0.1:{}

Log notice stdout
",
        tor_data_dir.display(),
        tor_data_dir.join("hidden_service").display(),
        hidden_service_port
    );
    println!("writing torrc");
    tokio::fs::write(torrc_path, content).await?;
    Ok(())
}

async fn start_tor(hidden_service_port: u16) -> Result<Child> {
    generate_tor_config(hidden_service_port).await?;
    let torrc_path = format!("/tmp/torrc-{}", std::process::id());

    let mut tor_process = Command::new("tor")
        .arg("-f")
        .arg(&torrc_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to spawn tor process")?;

    if let Some(stdout) = tor_process.stdout.take() {
        let mut reader = BufReader::new(stdout).lines();
        while let Some(line) = reader.next_line().await? {
            println!("Tor: {}", line);
            if line.contains("Bootstrapped 100%") {
                break;
            }
        }
    }

    let (_, tor_data_dir) = create_data_directories();
    let hostname_path = tor_data_dir.join("hidden_service").join("hostname");

    for _ in 0..30 {
        if tokio::fs::metadata(&hostname_path).await.is_ok() {
            let onion_address = determine_onion_address()?;
            println!("Your service is live at: {}", onion_address.trim());
            break;
        }
        sleep(Duration::from_secs(1)).await;
    }

    Ok(tor_process)
}

async fn start_http_server(port: u16) -> Result<()> {
    let addr = format!("127.0.0.1:{}", port);
    let listener = TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {}", addr))?;

    println!("HTTP server listening on {}", addr);
    println!("This will be exposed as a Tor hidden service");
    println!("Press Ctrl+C to stop");

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, addr).await {
                        eprintln!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Failed to accept connection: {}", e);
            }
        }
    }
}

pub async fn setup_tor_and_http(port: u16) -> Result<()> {
    println!("Setting up Tor onion service...");
    start_tor(port).await?;
    start_http_server(port).await?;
    Ok(())
}
fn encrypt_message_for_peer(message: &str, onion_peer: &str) -> Result<Vec<u8>> {
    let contacts = load_contacts_from_json();
    let contact = contacts
        .iter()
        .find(|c| c.onion_address == onion_peer)
        .ok_or_else(|| anyhow::anyhow!("Contact not found"))?;

    if contact.pk.is_empty() {
        return Err(anyhow::anyhow!("No public key for contact"));
    }

    let their_pk =
        parse_public_key(&contact.pk).ok_or_else(|| anyhow::anyhow!("Invalid public key"))?;

    let (_, my_sk) = crypto_setup();
    let encrypted = encrypt_message(message.as_bytes(), &their_pk, &my_sk);
    Ok(encrypted)
}

fn decrypt_message_from_peer(encrypted_data: &[u8], onion_peer: &str) -> Result<String> {
    let contacts = load_contacts_from_json();
    let contact = contacts
        .iter()
        .find(|c| c.onion_address == onion_peer)
        .ok_or_else(|| anyhow::anyhow!("Contact not found"))?;

    if contact.pk.is_empty() {
        return Err(anyhow::anyhow!("No public key for contact"));
    }

    let their_pk =
        parse_public_key(&contact.pk).ok_or_else(|| anyhow::anyhow!("Invalid public key"))?;

    let (_, my_sk) = crypto_setup();
    let decrypted = decrypt_message(encrypted_data, &their_pk, &my_sk)
        .ok_or_else(|| anyhow::anyhow!("Failed to decrypt message"))?;

    String::from_utf8(decrypted).map_err(|e| anyhow::anyhow!("Invalid UTF-8: {}", e))
}

pub async fn send_message_to_peer(message: &str, onion_peer: &str, port: u16) -> Result<()> {
    let mut stream = connect_to_peer(onion_peer, port).await?;
    let onion_address = determine_onion_address()?;

    if check_if_first_contact(onion_peer) {
        handshake(onion_peer).await?;
    }

    let message_to_send = match encrypt_message_for_peer(message, onion_peer) {
        Ok(encrypted) => {
            let encoded = general_purpose::STANDARD.encode(encrypted);
            format!("ENCRYPTED_MSG:{} FROM:{}", encoded, onion_address)
        }
        Err(_) => {
            format!("MSG:{} FROM:{}", message, onion_address)
        }
    };

    stream.write_all(message_to_send.as_bytes()).await?;
    stream.flush().await?;
    handle_outgoing_message(message, onion_peer).await;
    Ok(())
}

fn decode_encrypted_message(message: &str) -> Option<(Vec<u8>, &str)> {
    let message = message.trim().strip_prefix("ENCRYPTED_MSG:")?;
    let pos_of_from = message.rfind(" FROM:")?;
    let encrypted_b64 = &message[0..pos_of_from];
    let sender = &message[pos_of_from + 6..];
    let encrypted_data = general_purpose::STANDARD.decode(encrypted_b64).ok()?;
    Some((encrypted_data, sender))
}

async fn handle_incoming_message(message: &str) -> Option<()> {
    let (message_body, sender) = if message.starts_with("ENCRYPTED_MSG:") {
        let (encrypted_data, sender) = decode_encrypted_message(message)?;
        let decrypted_message = match decrypt_message_from_peer(&encrypted_data, sender) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                eprintln!("Failed to decrypt message from {}: {}", sender, e);
                return Some(());
            }
        };
        let message_body_with_newline = String::from("RECEIVED: ") + &decrypted_message + "\n";
        (message_body_with_newline, sender)
    } else {
        let (message_body, sender) = decode_incoming_message(message)?;
        (message_body, sender)
    };

    let (data_dir, _) = create_data_directories();
    let message_dir = data_dir.join("messages");
    let message_file = message_dir.join(sender);

    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(message_file)
        .await
        .ok()?;

    file.write_all(message_body.as_bytes()).await.ok()?;
    Some(())
}

async fn handle_connection(mut stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
    println!("New connection from: {}", addr);

    let mut buffer = [0; 2048];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .context("Failed to read from connection")?;

    if bytes_read > 0 {
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        if request.starts_with("MSG:") || request.starts_with("ENCRYPTED_MSG:") {
            handle_incoming_message(&request).await;
        } else if request.starts_with("HANDSHAKE:") {
            if let Err(e) = handle_handshake(&request).await {
                eprintln!("Failed to handle handshake: {}", e);
            }
        }
        println!("Received request:\n{}", request);
    }

    Ok(())
}

pub fn can_encrypt_to_contact(onion_address: &str) -> bool {
    let contacts = load_contacts_from_json();
    contacts
        .iter()
        .find(|c| c.onion_address == onion_address)
        .map_or(false, |c| !c.pk.is_empty())
}
