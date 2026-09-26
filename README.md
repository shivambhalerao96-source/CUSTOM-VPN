# CUSTOM-VPN

A custom VPN implementation built from scratch, with a focus on a minimal TUN-based architecture, UDP transport, and Libsodium-backed crypto.

## High-level architecture

This project is structured as a small VPN system with three main runtime parts:

1. Client side
   - creates a TUN interface for routing local traffic;
   - performs the UDP handshake with the VPN server;
   - encrypts and decrypts packets using per-session keys;
   - sends packets from TUN into the server and writes packets from the server back into TUN.

2. Server side
   - binds a UDP socket and accepts client connections;
   - allocates virtual IP addresses;
   - derives per-client session keys from the X25519 shared secret;
   - receives encrypted packets from clients, decrypts them, and forwards traffic to the real network or to the target host;
   - manages NAT/forwarding rules so VPN traffic can leave the host.

3. Shared crypto and networking core
   - X25519 key exchange and session key derivation;
   - packet encryption/decryption and replay protection;
   - TUN interface setup and routing utilities.

The project is split into logical subsystems, which are reflected in the directory structure:

- `client/` — client startup, handshake, transport threads, disconnect flow
- `server/` — server entry point and packet forwarding logic
- `crypto/` — handshake, session keys, AEAD packet crypto, replay protection
- `tun/` — Linux TUN interface creation and setup
- `frontend/` — Qt-based UI shell
- `docs/` — layer-by-layer protocol and security notes
- `tests/` — layer-specific validation tests

## Runtime flow

### 1. Client starts the connection

The client creates a TUN interface and starts a UDP connection to the VPN server. It also prepares the encryption keys needed for the session.

Once the server accepts the connection, the client is assigned a VPN IP address and the tunnel is ready to carry traffic.

### 2. Data is captured from the system

The operating system sends regular network traffic into the TUN interface. This is where the VPN takes over the traffic before it leaves the machine.

The client reads that traffic, encrypts it using the session keys, and sends it to the server over UDP.

### 3. Server receives and forwards traffic

The server receives the encrypted UDP packets, decrypts them, and forwards the traffic to the correct destination on the real network.

When the response comes back, the server encrypts it again and sends it back to the client.

### 4. Client delivers traffic back to the system

The client receives the encrypted reply from the server, decrypts it, and writes it back into the TUN interface. From there, the operating system delivers it to the application that requested it.

In simple terms, the flow is:

- app traffic enters the TUN interface
- client encrypts and sends it over UDP
- server decrypts and forwards it
- response comes back through the same path
- client decrypts and sends it to the app

This project uses a TUN interface, UDP sockets, and Libsodium-based encryption to build that tunnel in a simple and understandable way.

## Security layers

The project is organized around a layered security model that mirrors the documentation in `docs/`.

### Layer 1: Ephemeral X25519 key agreement

The client and server independently generate ephemeral X25519 key pairs and exchange public keys during the handshake. The shared secret is derived locally and never transmitted.

### Layer 2: Session-key derivation

From the X25519 shared secret, the project derives two directional symmetric keys using Libsodium KDF functions. The keys are used separately for traffic in each direction.

### Layer 3: Packet encryption

Each VPN packet is encrypted using Libsodium’s XChaCha20-Poly1305 AEAD primitive. Each packet uses a fresh nonce and the corresponding directional key.

### Layer 4: Integrity and authentication

Authentication is built into the AEAD tag validation step. Decryption fails if the tag is invalid, and the packet is dropped before it is written to TUN.

### Layer 5: Replay protection

The project includes replay-protection logic in `crypto/replay_protection.cpp` and associated tracking in the transport and forwarding path. This is intended to prevent duplicate or reordered packets from being accepted.

## Current status and limitations

This implementation is a working prototype rather than a production-grade VPN. The current scope includes:

- secure session key establishment;
- packet encryption and integrity protection;
- TUN-based client/server traffic forwarding;
- basic replay protection and sequence tracking;
- server-side NAT/forwarding setup.

Important caveats:

- the handshake is currently unauthenticated, so the system does not yet protect against active man-in-the-middle attacks;
- key rotation is not yet implemented;
- packet sequencing and replay protection are still being matured as part of the ongoing protocol design;
- routing and network setup are Linux-specific and depend on TUN and `iptables`/`ip6tables` tooling.

## Build summary

The project is built with CMake. The main targets are:

- `vpn_client` — client binary
- `vpn_server` — server binary
- `vpn_frontend` — optional Qt frontend

The build configuration is defined in `CMakeLists.txt` and links the crypto and TUN logic into the executables.

## Typical end-to-end flow

A normal VPN session looks like this:

```text
Application traffic
      |
      v
Linux TUN interface
      |
      v
client client1.cpp / tunToServer()
      |
      v
XChaCha20-Poly1305 encrypt + session key
      |
      v
UDP packet to VPN server
      |
      v
server/forward.cpp
      |
      v
decrypt + forward to external network / target host
      |
      v
response comes back through the same encrypted UDP path
      |
      v
serverToTun() writes packet into TUN
      |
      v
application receives data
```

This is the basic architecture of the project: TUN on the client, encrypted UDP transport in the middle, and a forwarding server on the other side doing NAT and packet translation.

## Validation notes

The crypto layer has been validated by:

- compiling and linking the client and server against Libsodium;
- deriving keys independently from both sides of an X25519 exchange;
- verifying that matching directions produce equal keys;
- verifying that opposite directions produce different keys.

These checks are part of the project’s layered protocol validation story and are documented further in the `docs/` directory.

## Running the code
After cloning the repository first install the libsodium library used for cryptography and qt6 library needed for frontend integration and cmake files for running the vpn frontend

```
sudo apt update
sudo apt install build-essential cmake qt6-base-dev
sudo apt install libsodium-dev
```
## Compilation

To configure and compile the project (both the GUI frontend and the client):

```bash
cmake -B build -S .
cmake --build build -j$(nproc)
```

- `cmake -B build -S .` creates the `build/` folder and configures the project.
- `cmake --build build -j$(nproc)` compiles all executables in parallel using all available CPU cores.

If you make changes later and want to recompile, simply run:
```bash
cmake --build build -j$(nproc)
```

## Running the Application

After compiling, navigate into the build folder (or run directly from root):

### 1. GUI Frontend (Recommended)
The frontend requires `sudo` permissions to create and configure the `tun0` interface:
```bash
sudo ./build/vpn_frontend
```
*(Or `cd build && sudo ./vpn_frontend`)*

### 2. Standalone Client in CLI
If you prefer running the client directly from the command line:
```bash
sudo ./build/vpn_client <SERVER_IP>
```

