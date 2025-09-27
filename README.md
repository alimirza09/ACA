# Another Chat App (ACA)
A true **P2P** private instant messaging app written in Rust.

## Features
- **End-to-end encrypted**.
- **True P2P**: no central servers, no bootstrap nodes.
- **No timestamps**: less metadata for the glowies.
- **Limited chat history in the GUI**L only a small portion of chat history is visible, giving less context to onlookers.

## Pitfalls
- The onion address is still unencrypted and can be viewed by your network admin, ISP, or relay node admins.
- No built-in firewall  you are exposing yourself to the web.
- No rate-limiting.

## Technical Details
The chat app works by creating a Tor onion service and communicating with peers through WebSockets.  
The first message is sent after a handshake where nodes exchange their public keys.  

- Public/private keys: **Curve25519 elliptic curve Diffie–Hellman (ECDH)**  
- Message encryption and authentication: **XSalsa20 stream cipher + Poly1305 MAC**

## Licensing
This project is licensed under the GNU General Public License v3 (GPL-3.0-or-later).  
See the [LICENSE](LICENSE) file for details or visit <https://www.gnu.org/licenses/>.
