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

pub fn can_encrypt_to_contact(onion_address: &str) -> bool {
    let contacts = load_contacts_from_json();
    contacts
        .iter()
        .find(|c| c.onion_address == onion_address)
        .map_or(false, |c| !c.pk.is_empty())
}
fn decode_handshake(request: &str) -> Option<(&str, &str)> {
    let request = request.trim().strip_prefix("HANDSHAKE:")?;
    let parts: Vec<&str> = request.splitn(2, ':').collect();
    if parts.len() == 2 {
        let onion_peer = parts[0].trim();
        let pk_peer_b64 = parts[1].trim();
        Some((onion_peer, pk_peer_b64))
    } else {
        None
    }
}

async fn handle_handshake(request: &str) -> Result<()> {
    println!("Received handshake request: {}", request);

    if let Some((onion_peer, pk_peer_b64)) = decode_handshake(request) {
        println!(
            "Decoded handshake from {} with key {}",
            onion_peer,
            &pk_peer_b64[..20]
        );

        let contacts = load_contacts_from_json();
        if let Some(_existing_contact) = contacts.iter().find(|c| c.onion_address == onion_peer) {
            println!("Updating existing contact {} with public key", onion_peer);
            update_contact_pk(onion_peer, pk_peer_b64)?;
        } else {
            println!("Storing pending handshake for new contact {}", onion_peer);
            store_pending_handshake(onion_peer, pk_peer_b64)?;
        }

        println!("Sending handshake response to {}", onion_peer);
        handshake(onion_peer).await?;
    } else {
        println!("Failed to decode handshake request: {}", request);
    }
    Ok(())
}

fn encrypt_message_for_peer(message: &str, onion_peer: &str) -> Result<Vec<u8>> {
    let contacts = load_contacts_from_json();
    let contact = contacts
        .iter()
        .find(|c| c.onion_address == onion_peer)
        .ok_or_else(|| anyhow::anyhow!("Contact {} not found", onion_peer))?;

    if contact.pk.is_empty() {
        return Err(anyhow::anyhow!("No public key for contact {}", onion_peer));
    }

    println!(
        "Encrypting message for {} with key {}",
        onion_peer,
        &contact.pk[..20]
    );

    let their_pk = parse_public_key(&contact.pk)
        .ok_or_else(|| anyhow::anyhow!("Invalid public key for {}", onion_peer))?;

    let (_, my_sk) = crypto_setup();
    let encrypted = encrypt_message(message.as_bytes(), &their_pk, &my_sk);
    println!(
        "Message encrypted successfully, size: {} bytes",
        encrypted.len()
    );
    Ok(encrypted)
}

pub async fn force_handshake_with_contact(onion_peer: &str) -> Result<()> {
    println!("Forcing handshake with {}", onion_peer);
    handshake(onion_peer).await?;
    println!("Handshake initiated with {}", onion_peer);
    Ok(())
}

async fn handshake(onion_peer: &str) -> Result<()> {
    let (pk, _) = crypto_setup();
    let pk_b64 = encode_public_key(&pk);
    let onion_address = determine_onion_address()?;

    println!("Performing handshake: sending our key to {}", onion_peer);

    let mut stream = connect_to_peer(onion_peer, 80)
        .await
        .context("Failed to connect for handshake")?;

    let handshake = format!("HANDSHAKE:{}:{}", onion_address.trim(), pk_b64);
    println!("Sending handshake: {}", handshake);

    stream
        .write_all(handshake.as_bytes())
        .await
        .context("Failed to send handshake")?;

    stream.flush().await?;
    Ok(())
}

pub async fn test_peer_connection(onion_peer: &str, port: u16) -> Result<bool> {
    println!("Testing connection to {}:{}", onion_peer, port);

    match connect_to_peer(onion_peer, port).await {
        Ok(mut stream) => {
            println!("✓ Successfully connected to {}:{}", onion_peer, port);

            let test_msg = "PING\n";
            match stream.write_all(test_msg.as_bytes()).await {
                Ok(_) => {
                    println!("✓ Successfully sent test message");
                    Ok(true)
                }
                Err(e) => {
                    println!("✗ Failed to send test message: {}", e);
                    Ok(false)
                }
            }
        }
        Err(e) => {
            println!("✗ Failed to connect to {}:{} - {}", onion_peer, port, e);
            Ok(false)
        }
    }
}

async fn connect_to_peer_with_timeout(
    onion_peer: &str,
    port: u16,
    timeout_secs: u64,
) -> Result<TcpStream> {
    println!(
        "Connecting to {}:{} (timeout: {}s)",
        onion_peer, port, timeout_secs
    );

    let connect_future = async {
        Socks5Stream::connect("127.0.0.1:9050", format!("{}:{}", onion_peer, port))
            .await
            .map(|stream| stream.into_inner())
            .context("SOCKS5 connection failed")
    };

    match tokio::time::timeout(Duration::from_secs(timeout_secs), connect_future).await {
        Ok(result) => match result {
            Ok(stream) => {
                println!("✓ Connected successfully to {}:{}", onion_peer, port);
                Ok(stream)
            }
            Err(e) => {
                println!("✗ Connection failed: {}", e);
                Err(e)
            }
        },
        Err(_) => {
            println!("✗ Connection timed out after {}s", timeout_secs);
            Err(anyhow::anyhow!("Connection timeout"))
        }
    }
}

async fn connect_to_peer(onion_peer: &str, port: u16) -> Result<TcpStream> {
    connect_to_peer_with_timeout(onion_peer, port, 30).await
}

pub async fn test_tor_connectivity() -> Result<()> {
    println!("Testing Tor connectivity...");

    match TcpStream::connect("127.0.0.1:9050").await {
        Ok(_) => println!("✓ Tor SOCKS5 proxy is accessible"),
        Err(e) => {
            println!("✗ Cannot connect to Tor SOCKS5 proxy: {}", e);
            return Err(anyhow::anyhow!("Tor proxy not accessible"));
        }
    }

    match connect_to_peer("3g2upl4pq6kufc4m.onion", 80).await {
        Ok(_) => println!("✓ Can connect to onion services"),
        Err(e) => {
            println!("✗ Cannot connect to onion services: {}", e);
            return Err(anyhow::anyhow!("Cannot reach onion services"));
        }
    }

    println!("✓ Tor connectivity test passed");
    Ok(())
}

pub async fn debug_connection_stack(onion_peer: &str) -> Result<()> {
    println!("=== Connection Debug Stack for {} ===", onion_peer);

    println!("\n1. Testing Tor connectivity...");
    test_tor_connectivity().await?;

    println!("\n2. Testing peer connection...");
    test_peer_connection(onion_peer, 80).await?;

    println!("\n3. Checking our own service...");
    let our_address = determine_onion_address()?;
    println!("Our onion address: {}", our_address);

    println!("\n4. Contact status...");
    let contacts = load_contacts_from_json();
    if let Some(contact) = contacts.iter().find(|c| c.onion_address == onion_peer) {
        println!(
            "Contact found: {} (pk: {})",
            contact.alias,
            if contact.pk.is_empty() {
                "MISSING"
            } else {
                "PRESENT"
            }
        );
    } else {
        println!("Contact not found in contacts list");
    }

    println!("\n=== Debug Complete ===");
    Ok(())
}

async fn handshake_with_response(onion_peer: &str) -> Result<()> {
    let (pk, _) = crypto_setup();
    let pk_b64 = encode_public_key(&pk);
    let onion_address = determine_onion_address()?;

    println!("Performing handshake with response waiting: {}", onion_peer);

    let mut stream = connect_to_peer(onion_peer, 80)
        .await
        .context("Failed to connect for handshake")?;

    let handshake = format!("HANDSHAKE:{}:{}", onion_address.trim(), pk_b64);
    println!("Sending handshake: {}", handshake);

    stream
        .write_all(handshake.as_bytes())
        .await
        .context("Failed to send handshake")?;
    stream.flush().await?;

    println!("Waiting for handshake response...");
    let mut buffer = [0; 2048];

    match tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await {
        Ok(Ok(bytes_read)) if bytes_read > 0 => {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            println!("Received handshake response: {}", response);

            if response.starts_with("HANDSHAKE:") {
                handle_handshake(&response).await?;
                println!("✓ Handshake completed successfully");
            } else {
                println!("⚠ Received non-handshake response: {}", response);
            }
        }
        Ok(Ok(_)) => {
            println!("⚠ Received empty response");
        }
        Ok(Err(e)) => {
            println!("⚠ Error reading handshake response: {}", e);
        }
        Err(_) => {
            println!("⚠ Timeout waiting for handshake response");
        }
    }

    Ok(())
}

pub async fn send_message_to_peer_fixed(message: &str, onion_peer: &str, port: u16) -> Result<()> {
    let onion_address = determine_onion_address()?;

    let contacts = load_contacts_from_json();
    let needs_handshake = contacts
        .iter()
        .find(|c| c.onion_address == onion_peer)
        .map_or(true, |c| c.pk.is_empty());

    if needs_handshake {
        println!("Contact needs handshake, testing connectivity first...");

        match test_peer_connection(onion_peer, port).await {
            Ok(true) => {
                println!("Peer is reachable, proceeding with handshake");
                handshake_with_response(onion_peer).await?;

                tokio::time::sleep(Duration::from_millis(500)).await;

                let updated_contacts = load_contacts_from_json();
                let has_key = updated_contacts
                    .iter()
                    .find(|c| c.onion_address == onion_peer)
                    .map_or(false, |c| !c.pk.is_empty());

                if has_key {
                    println!("✓ Handshake successful, encryption available");
                } else {
                    println!("⚠ Handshake completed but no key received");
                }
            }
            Ok(false) => {
                return Err(anyhow::anyhow!(
                    "Peer is reachable but not responding correctly"
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Cannot reach peer {}: {}", onion_peer, e));
            }
        }
    }

    let mut stream = connect_to_peer(onion_peer, port).await?;

    let message_to_send = match encrypt_message_for_peer(message, onion_peer) {
        Ok(encrypted) => {
            let encoded = general_purpose::STANDARD.encode(encrypted);
            println!("Sending encrypted message to {}", onion_peer);
            format!("ENCRYPTED_MSG:{} FROM:{}", encoded, onion_address)
        }
        Err(e) => {
            println!(
                "Failed to encrypt message for {}: {}, sending plaintext",
                onion_peer, e
            );
            format!("MSG:{} FROM:{}", message, onion_address)
        }
    };

    stream.write_all(message_to_send.as_bytes()).await?;
    stream.flush().await?;
    handle_outgoing_message(message, onion_peer).await;

    println!("Message sent successfully to {}", onion_peer);
    Ok(())
}

pub fn debug_contact_status(onion_address: &str) {
    let contacts = load_contacts_from_json();
    if let Some(contact) = contacts.iter().find(|c| c.onion_address == onion_address) {
        println!("Contact status for {}:", onion_address);
        println!("  Alias: {}", contact.alias);
        let key_status = if contact.pk.is_empty() {
            "MISSING".to_string()
        } else {
            format!("PRESENT ({}...)", &contact.pk[..20])
        };
        println!("  Public Key: {}", key_status);
        println!("  Can Encrypt: {}", can_encrypt_to_contact(onion_address));
    } else {
        println!("Contact {} not found", onion_address);
    }
}
pub async fn send_message_to_peer(message: &str, onion_peer: &str, port: u16) -> Result<()> {
    let onion_address = determine_onion_address()?;

    let contacts = load_contacts_from_json();
    let needs_handshake = contacts
        .iter()
        .find(|c| c.onion_address == onion_peer)
        .map_or(true, |c| c.pk.is_empty());

    if needs_handshake {
        println!("Starting handshake with {}", onion_peer);

        let our_address = determine_onion_address()?;
        let (our_pk, _) = crypto_setup();
        let our_pk_b64 = encode_public_key(&our_pk);

        let mut stream = connect_to_peer(onion_peer, port).await?;
        let handshake_msg = format!("HANDSHAKE_REQUEST:{}:{}", our_address.trim(), our_pk_b64);

        stream.write_all(handshake_msg.as_bytes()).await?;
        stream.flush().await?;

        let mut buffer = [0; 2048];
        match tokio::time::timeout(Duration::from_secs(15), stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) if bytes_read > 0 => {
                let response = String::from_utf8_lossy(&buffer[..bytes_read]);

                if response.starts_with("HANDSHAKE_RESPONSE:") {
                    if let Some((peer_address, peer_key)) = decode_handshake_response(&response) {
                        if let Some(_) = contacts.iter().find(|c| c.onion_address == peer_address) {
                            update_contact_pk(peer_address, peer_key)?;
                        } else {
                            store_pending_handshake(peer_address, peer_key)?;
                        }

                        let ack_msg =
                            format!("HANDSHAKE_ACK:{}:{}", our_address.trim(), our_pk_b64);
                        stream.write_all(ack_msg.as_bytes()).await?;
                        stream.flush().await?;
                    }
                } else if response.starts_with("HANDSHAKE:") {
                    handle_handshake(&response).await?;
                }
            }
            _ => {}
        }

        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    let mut stream = connect_to_peer(onion_peer, port).await?;

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

async fn handle_connection(mut stream: TcpStream, addr: std::net::SocketAddr) -> Result<()> {
    println!("New connection from: {}", addr);

    let mut buffer = [0; 2048];
    let bytes_read = stream.read(&mut buffer).await?;

    if bytes_read > 0 {
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);

        if request.starts_with("HANDSHAKE_REQUEST:") {
            handle_handshake_request(&request, &mut stream).await?;
        } else if request.starts_with("HANDSHAKE_ACK:") {
            handle_handshake_ack(&request).await?;
        } else if request.starts_with("HANDSHAKE:") {
            handle_handshake_old_format(&request, &mut stream).await?;
        } else if request.starts_with("MSG:") || request.starts_with("ENCRYPTED_MSG:") {
            handle_incoming_message(&request).await;
        }
    }

    Ok(())
}

async fn handle_handshake_request(request: &str, stream: &mut TcpStream) -> Result<()> {
    if let Some((peer_address, peer_key)) = decode_handshake_request(request) {
        let contacts = load_contacts_from_json();
        if let Some(_) = contacts.iter().find(|c| c.onion_address == peer_address) {
            update_contact_pk(peer_address, peer_key)?;
        } else {
            store_pending_handshake(peer_address, peer_key)?;
        }

        let our_address = determine_onion_address()?;
        let (our_pk, _) = crypto_setup();
        let our_pk_b64 = encode_public_key(&our_pk);
        let response = format!("HANDSHAKE_RESPONSE:{}:{}", our_address.trim(), our_pk_b64);

        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;

        let mut buffer = [0; 1024];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer))
            .await
            .ok();
    }

    Ok(())
}

async fn handle_handshake_ack(request: &str) -> Result<()> {
    if let Some((peer_address, peer_key)) = decode_handshake_ack(request) {
        let contacts = load_contacts_from_json();
        if let Some(_) = contacts.iter().find(|c| c.onion_address == peer_address) {
            update_contact_pk(peer_address, peer_key)?;
        } else {
            store_pending_handshake(peer_address, peer_key)?;
        }
    }

    Ok(())
}

async fn handle_handshake_old_format(request: &str, stream: &mut TcpStream) -> Result<()> {
    if let Some((peer_address, peer_key)) = decode_handshake(request) {
        let contacts = load_contacts_from_json();
        if let Some(_) = contacts.iter().find(|c| c.onion_address == peer_address) {
            update_contact_pk(peer_address, peer_key)?;
        } else {
            store_pending_handshake(peer_address, peer_key)?;
        }

        let our_address = determine_onion_address()?;
        let (our_pk, _) = crypto_setup();
        let our_pk_b64 = encode_public_key(&our_pk);
        let response = format!("HANDSHAKE:{}:{}", our_address.trim(), our_pk_b64);

        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
    }

    Ok(())
}

fn decode_handshake_request(request: &str) -> Option<(&str, &str)> {
    let request = request.trim().strip_prefix("HANDSHAKE_REQUEST:")?;
    let colon_pos = request.find(':')?;
    let peer_address = request[..colon_pos].trim();
    let peer_key = request[colon_pos + 1..].trim();
    Some((peer_address, peer_key))
}

fn decode_handshake_response(response: &str) -> Option<(&str, &str)> {
    let response = response.trim().strip_prefix("HANDSHAKE_RESPONSE:")?;
    let colon_pos = response.find(':')?;
    let peer_address = response[..colon_pos].trim();
    let peer_key = response[colon_pos + 1..].trim();
    Some((peer_address, peer_key))
}

fn decode_handshake_ack(ack: &str) -> Option<(&str, &str)> {
    let ack = ack.trim().strip_prefix("HANDSHAKE_ACK:")?;
    let colon_pos = ack.find(':')?;
    let peer_address = ack[..colon_pos].trim();
    let peer_key = ack[colon_pos + 1..].trim();
    Some((peer_address, peer_key))
}
