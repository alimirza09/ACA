use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs::OpenOptions;
use std::io::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
