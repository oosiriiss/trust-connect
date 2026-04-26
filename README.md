# Trust connect

A C++23 implementation of a **Trusted Third Party (TTP) authentication system** built from scratch on top of raw TCP sockets and OpenSSL. Three communicating processes - a TTP certificate authority, a service server, and a client - perform a multi-step cryptographic handshake to establish a mutually authenticated, AES-256-GCM encrypted session, with no pre-shared secrets.

---

## Architecture

```
 ┌──────┐              ┌──────┐             ┌──────┐ 
 │Client├◄────────────►│TTP CA│◄───────────►│Server│ 
 └──┬───┘              └──────┘             └──▲───┘ 
    └──────────────────────────────────────────┘     
```

| Entity | Role |
|---|---|
| `ttp-app` | Certificate Authority - issues X.509 certs, verifies certificates, creates and distributes session key |
| `server-app` | Server that offers some kind of service, authenticates client with TTP |
| `client-app` | Client that requests a service from Server |

---

## Building the Project

### Prerequisites

- CMake version: >= 3.13 
- Ninja (Tested with ninja version 1.13.2)
- C++23 compiler (G++ 15.2.1 used for development)
- OpenSSL development version available on the system
- OpenGL available on the system (for client's GUI)
- GLFW version: 3.4 (Automatically fetched with CMake)
- [cppli](https://github.com/oosiriiss/cppli) version: 0.2.1 (Automatically fetched with CMake)
- nlohmann_json version: 3.12.0 (Automatically fetched with CMake)

### Build

```bash
git clone https://github.com/trust-connect trust-connect
cd trust-connect
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

#### CMake options you can toggle:

| Option | Default | Description |
|---|---|---|
| `BUILD_CLIENT` | `ON` | Build the ImGui/OpenGL GUI client |
| `COMPILE_TESTS` | `ON` | Build unit tests |
| `BUILD_DOCS` | `ON` | Generate Doxygen documentation |
| `ENABLE_DEBUG_UTILS` | `ON` | Enable debug assertions |

### Run with Docker Compose

The provided `docker-compose.yml` builds and starts the TTP and server in separate containers and wires up the ports automatically:

```bash
docker compose up --build
```
Then run the client locally:

```bash
./build/client-app --server-ip 127.0.0.1 --server-port 6600 \
                   --ttp-ip 127.0.0.1    --ttp-port 6601
```

### CLI reference

Each application has a CLI interface. You can view more information by running the executable with a ```--help``` option 
```bash
./build/client-app --help
./build/server-app --help
./build/ttp-app --help
```

---

## Protocol & Handshake Flow

> [!NOTE]  
> Session tickets are  not used in the current architecture, but were left for future enhancements

All packets share a binary format:

```
                                                                
 ┌────┐┌──────┐┌───────────────────────┐                        
 │Type││Length││Variable length payload│                        
 └────┘└──────┘└───────────────────────┘                        
   1       4             <length>         # Number of bytes     
                                                                
```
                                                                

The payload is a JSON object whose keys depend on the packet type. Binary fields (ciphertext, signatures, keys) are Base64-encoded before embedding in JSON.


### Phase 1 - Certificate Registration

Client and server both read TTP's public certificate from a secure location (in this case a file) to minimize network threat potential.

Performed once, before any session. The client and server each obtain an X.509 certificate signed by the TTP's CA.

```
Client / Server                          TTP
      │                                   │
      │── CertificateRequest ────────────►│  { id (RSA-encrypted with TTP's key), public_key_pem }
      │                                   │  TTP decrypts ID, issues X.509 cert
      │◄─ CertificateResponse ────────────│  { certificate_pem }
      │   (client verifies cert against   │
      │    TTP's CA cert)                 │
```

The ID is encrypted with the TTP's RSA public key so the TTP is the only entity that can read it.

---

### Phase 2 - Authentication Handshake

Both the client and server connect to the TTP simultaneously. The TTP acts as a broker, verifying all certificates and distributing a freshly generated AES-256 session key to both parties.

```
Client                    Server                      TTP
  │                         │                          │
  │─── InitiateAuth ────────┼─────────────────────────►│  {role=Requester, cert PEM}
  │                         │─── InitiateAuth ────────►│  {role=Service, cert PEM}
  │                         │                          │  TTP verifies both certs againts its, and stores
  │                         │                          │  connections for further data transfer
  │◄── InitiateAuthOk ──────┼──────────────────────────│   
  │                         │◄─ InitiateAuthOk ────────│
  │                         │                          │
  │─── ServiceRequest ─────►│                          │  {user_public_cert_pem}
  │                         │                          │
  │                         │─── ServerAuthRequest ───►│  {user_public_cert_pem, server_public_cert_pem}
  │                         │                          │    
  │                         │                          │  TTP verifies both certificates 
  │                         │◄─ ServerAuthOk ──────────│  sends ServerAuthOk
  │◄── ServerAuthOk ───────────────────────────────────│  (signed session ticket) { session_id, client_cn, server_cn, signature }
  │                         │                          │
  │◄── UserAuthRedirect ───────────────────────────────│
  │                         │                          │
  │─── UserAuthDataSubmit ────────────────────────────►│  { user_cert_pem, session_id }
  │                         │                          │    
  │                         │                          │  TTP re-verifies user Generates AES-256 key

  │◄── UserAuthOk ──────────────────────────────────── │  { session_key } (encrypted with client's public RSA key)
  │                         │◄─ UserAuthOk ────────────│  { session_key } (encrypted with Server's public RSA key)
```


The session ticket sent in `ServerAuthOk` is signed with the TTP's RSA private key and verified by the client using the TTP's public key, ensuring it was not tampered with.

---

### Phase 3 - Encrypted Data Exchange

Once both sides hold the same AES-256-GCM session key, the TTP is no longer involved. and the connection with TTP may be closed.

```
Client                                   Server
  │─── DataRequest ───────────────────────►│  { request } Encrypted with session key
  │◄── DataResponse ────────────────────── │  { response } Encrypted with session key
```

---

# License

This project is licensed under MIT License. For further details see [License](./LICENSE)
