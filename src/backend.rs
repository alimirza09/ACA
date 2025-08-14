use crate::crypto::{encode_public_key, generate_and_store_keypair, load_keypair};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::box_::{PublicKey, SecretKey};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};
use tokio_socks::tcp::socks5::*;

#[derive(Serialize, Deserialize)]
pub struct Contact {
    onion_address: String,
    alias: String,
    pk: String,
}

async fn handshake(onion_peer: &str) -> Result<()> {
    let (data_dir, _) = create_data_directories();
    let message_dir = data_dir.join("messages");
    let message_file = message_dir.join(onion_peer);
    let (pk, _) = crypto_setup();
    let pk_b64 = encode_public_key(&pk);

    if !message_file.exists() {
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
pub async fn read_contacts() -> Result<Vec<Contact>> {
    let (data_dir, _) = create_data_directories();
    let contacts_file = data_dir.join("contacts").join("contacts.json");

    if !contacts_file.exists() {
        return Ok(Vec::new());
    }

    let data = tokio::fs::read(&contacts_file).await?;

    let contacts: Vec<Contact> = serde_json::from_slice(&data)?;

    Ok(contacts)
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

async fn handle_handshake(request: &str) -> Result<()> {
    let (onion_peer, pk_peer_b64) = decode_handshake(request).unwrap();
    Ok(())
}

fn check_if_first_contact(onion_peer: &str) -> bool {
    let (data_dir, _) = create_data_directories();
    let message_dir = data_dir.join("messages");
    let message_file = message_dir.join(onion_peer);
    message_file.exists()
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

pub async fn send_message_to_peer(message: &str, onion_peer: &str, port: u16) -> Result<()> {
    let mut stream = connect_to_peer(onion_peer, port).await?;
    let onion_address = determine_onion_address()?;
    if check_if_first_contact(onion_peer) {
        handshake(onion_peer).await?;
    }
    stream
        .write_all(format!("MSG:{} FROM:{}", message, onion_address).as_bytes())
        .await?;
    stream.flush().await?;
    handle_outgoing_message(message, onion_peer).await;
    Ok(())
}

async fn handle_outgoing_message(message: &str, receiver: &str) -> Option<()> {
    let (data_dir, _) = create_data_directories();
    let message_dir = data_dir.join("messages");
    let message_file = message_dir.join(receiver);
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

async fn handle_incoming_message(message: &str) -> Option<()> {
    let (message, sender) = decode_incoming_message(message)?;
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

    file.write_all(message.as_bytes()).await.ok()?;
    Some(())
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

async fn handle_connection(mut stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
    println!("New connection from: {}", addr);

    let mut buffer = [0; 1024];
    let bytes_read = stream
        .read(&mut buffer)
        .await
        .context("Failed to read from connection")?;

    if bytes_read > 0 {
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        if request.starts_with("MSG:") {
            handle_incoming_message(&request).await;
        } else if request.starts_with("HANDSHAKE:") {
            handle_handshake(&request).await?;
        }
        println!("Received request:\n{}", request);
    }

    Ok(())
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

pub async fn get_message_count(sender: &str) -> usize {
    let (data_dir, _) = create_data_directories();
    let message_file = data_dir.join("messages").join(sender);

    match tokio::fs::read_to_string(message_file).await {
        Ok(content) => content.lines().count(),
        Err(_) => 0,
    }
}

pub async fn setup_tor_and_http(port: u16) -> Result<()> {
    println!("Setting up Tor onion service...");
    start_tor(port).await?;
    start_http_server(port).await?;
    Ok(())
}
