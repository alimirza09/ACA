# Another Chat App (ACA) 💬
A true **P2P** private instant messaging app written in Rust.  
Because who needs friends when you have cryptography?

## Features ✨
- **End-to-end encryption**: so your messages are unreadable to everyone, including you in 6 months.  
- **True P2P**: no central servers, no bootstrap nodes, no corporate overlords.  
- **No timestamps**: less metadata for the glowies 🕵️.  
- **Limited chat history in the GUI**: only a handful of messages visible — because if you can’t remember what you said, it probably wasn’t that important.  

## Technical Details 🧩
ACA spins up a Tor onion service and talks to peers through WebSockets.  
The first message goes out after a cryptographic handshake where peers exchange their public keys (awkward first date vibes).  

- **Keys**: Curve25519 elliptic-curve Diffie–Hellman (ECDH) 🔑  
- **Encryption**: XSalsa20 stream cipher  
- **Authentication**: Poly1305 MAC (not the Apple one)  

## Security Considerations 🔒
⚠️ **ACA is experimental software. Do not trust it with state secrets, nuclear launch codes, or your OnlyFans password.**  

Even though it uses strong crypto, there are some "features":  

- **Forward Secrecy**  
  Nope. If your private key leaks, all your past chats are basically public fanfiction.  

- **Replay Attacks**  
  An attacker could resend old messages, so don’t be surprised if your friend suddenly says “hi” again… and again… and again.  

- **Metadata Exposure**  
  Messages are encrypted, but your onion address is still visible. Your ISP might not know what you’re saying, but they’ll know you’re up to *something*.  

- **Key Authentication**  
  No out-of-band verification. MITM attackers could catfish you with crypto.  

- **Denial of Service (DoS)**  
  No rate limiting. If someone floods your node, congrats, you just DDoS’d yourself.  

- **Limited Audit**  
  This code hasn’t been security-audited. The only eyes on it are mine, and I’ve been running on 3 hours of sleep.  

## Licensing ⚖️
This project is licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**.  
See the [LICENSE](LICENSE) file or <https://www.gnu.org/licenses/gpl-3.0.html>.  

## Disclaimer ⚠️
This software is provided *“as is”*, without warranty of any kind, except the warranty that it will definitely break at the worst possible time.  

ACA is a **research/hobby project**, not a drop-in replacement for Signal or Matrix.  
If you use this for anything serious: good luck, godspeed, and don’t call me.  
