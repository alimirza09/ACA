# Another Chat App (ACA)
A true **p2p** private instant messaging app made in rust.

## Features
- **End to End encrypted**.
- **True P2P**, no central servers no bootstrap nodes.
- **No Timestamps** less metadata for the glowies,
- **Limited Chat History in the GUI**, only some of the chat history can be seen in the GUI giving less context to onlookers.

## Pitfalls
- The onion address is still unencrypted and can be viewed by your network admin, ISP and the node admins.
- No built in Firewall you are exposing yourself to the Web.
- No Rate-Limitng

## Technical Details
The Chat App works by creating an onion service and talking to peer through web sockets. 
The first meessage is sent after a handshake in which the nodes exchange their public keys. 
The public and private keys are generated through **Curve25519 elliptic curve Diffie–Hellman (ECDH)**.
Each message is encrypted using **XSalsa20**.

## Licensing
This project is licensed under the GNU General Public License v3 (GPL-3.0-or-later).  
See the [LICENSE](LICENSE) file for details or visit <https://www.gnu.org/licenses/gpl.html>.
