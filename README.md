# Another Chat App (ACA)
A true **P2P** private instant messaging app written in Rust.

## Features
- **End-to-end encrypted**.
- **True P2P**: no central servers, no bootstrap nodes.
- **No timestamps**: less metadata for the glowies.
- **Limited chat history in the GUI**L only a small portion of chat history is visible, giving less context to onlookers.

## Technical Details
The chat app works by creating a Tor onion service and communicating with peers through WebSockets.  
The first message is sent after a handshake where nodes exchange their public keys.  

- Public/private keys: **Curve25519 elliptic curve Diffie–Hellman (ECDH)**  
- Message encryption and authentication: **XSalsa20 stream cipher + Poly1305 MAC**

## Security Considerations

ACA is experimental software. While it uses strong cryptographic primitives, there are important limitations:

- **Forward Secrecy**:  
  Messages are encrypted with long-term key pairs. If a private key is ever compromised, past messages could be decrypted. Forward secrecy (e.g., via ephemeral session keys) is not yet implemented.

- **Replay Attacks**:  
  The protocol does not currently include replay protection. An adversary could resend valid ciphertexts to trick clients into displaying old messages.

- **Metadata Exposure**:  
  While message contents are encrypted, Tor onion addresses and traffic patterns may still reveal who is talking to whom and when.

- **Key Authentication**:  
  Keys are exchanged directly between peers. Without an out-of-band verification method (fingerprints, QR codes, etc.), there is a risk of man-in-the-middle attacks.

- **Denial of Service (DoS)**:  
  No built-in rate limiting or resource controls exist, making nodes vulnerable to flooding or connection exhaustion.

- **Limited Audit**:  
  The codebase has not undergone a professional security audit. Use at your own risk.


## Licensing
This project is licensed under the GNU General Public License v3 (GPL-3.0-or-later).  
See the [LICENSE](LICENSE) file for details or visit <https://www.gnu.org/licenses/>.

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, 
including but not limited to the warranties of merchantability, fitness for a particular purpose 
and noninfringement. In no event shall the authors or copyright holders be liable for any claim, 
damages or other liability, whether in an action of contract, tort or otherwise, arising from, 
out of or in connection with the software or the use or other dealings in the software.  

This project is a research/hobby project and **should not be relied upon for secure communications**.  
Use at your own risk.

