use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::time::{Duration, sleep};

const FILE_PATH: &str = "messages.csv";
const USER_ID: &str = "userid";

pub fn handle_message(message: &str) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(false)
        .append(true)
        .open(FILE_PATH)
        .unwrap();
    let message_and_metadata = format!("{}, {} \n", message, USER_ID);
    file.write_all(message_and_metadata.as_bytes())?;
    Ok(())
}

async fn generate_tor_config(hidden_service_port: u16) -> Result<()> {
    let torrc_path = format!("/tmp/torrc-{}", std::process::id());
    let content = format!(
        "# Tor configuration for hidden service
DataDirectory /tmp/tor-data-{}
SocksPort 9050
ControlPort 9051
CookieAuthentication 1

HiddenServiceDir /tmp/tor-hidden-service-{}
HiddenServicePort 80 127.0.0.1:{}

Log notice stdout
",
        std::process::id(),
        std::process::id(),
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

    let hostname_path = format!("/tmp/tor-hidden-service-{}/hostname", std::process::id());
    for _ in 0..30 {
        if tokio::fs::metadata(&hostname_path).await.is_ok() {
            let onion_address = tokio::fs::read_to_string(&hostname_path).await?;
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
        println!("Received request:\n{}", request);

        let body = "<html><body><h1>Wassup</h1></body></html>";
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            body.len(),
            body
        );

        stream
            .write_all(response.as_bytes())
            .await
            .context("Failed to write response")?;
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
pub async fn setup_tor_and_http(port: u16) -> Result<()> {
    println!("Setting up Tor onion service...");

    start_tor(port).await?;

    start_http_server(port).await?;
    Ok(())
}
