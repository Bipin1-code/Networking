
# TCP-TLS Multi-Client Chat Server

A multi-client chat server with custom protocol and TLS encryption, written in C for Windows.

## Features

- Multi-client support using `select()`
- Custom application protocol with length-prefixed framing
- Commands: `/name`, `/msg`, `/list`, broadcast
- TLS encryption via OpenSSL
- Binary-safe message handling

## Files

| File | Description |
|------|-------------|
| `server.c` | TCP-TLS chat server |
| `client.c` | TCP-TLS chat client |
| `cert.pem` | Self-signed TLS certificate |
| `key.pem` | Private key (keep secret) |

## Build

Requires OpenSSL and MinGW/GCC.

Copy `libssl-3-x64.dll` and `libcrypto-3-x64.dll` next to the executables (or use MT libraries for static linking).

## Generate Certificate
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

## Compile 
```bash
gcc -Wall server.c -o server.exe -lws2_32 -lssl -lcrypto
gcc -Wall client.c -o client.exe -lws2_32 -lssl -lcrypto
```

## Protocol
[4-byte length (network order)][message payload]


## Known Issues

- `select()` limited to 64 sockets on Windows
- No authentication
- Self-signed certificate (clients must trust manually)
- No persistent message history


## Usage
1. Start server: `server.exe`
2. Start client(s): `client.exe`
3. Chat:
```text
/name Alice Set your nickname
/msg Bob hello Private message to Bob
/list Show online users
<anything else> Broadcast to all
```

## License
Learning project. Do whatever you want.
