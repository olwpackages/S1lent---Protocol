# S1lent / Universal IP

S1lent is an experimental network protocol designed around persistent encrypted sessions and Universal IP routing. Universal IP is the ordered routing model above S1lent; it is not a new IP protocol, address family, or replacement for IPv4/IPv6. S1lent is not an HTTP wrapper.

The prototype contains a TLS 1.3 server-authenticated handshake, per-session TLS-exported AES-256-GCM keys, route setup, replay checks, static routing, Windows UDP transport, a dynamically loaded Wintun adapter, separate node/client/server executables, and a two-node encrypted round-trip harness.

## Build (Windows, Visual Studio C++ workload)

OpenSSL 3 development headers and libraries are required. With CMake and OpenSSL installed:

```powershell
cmake -S . -B build -DOPENSSL_ROOT_DIR="C:/path/to/openssl"
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

Run the local encrypted IP packet check with `build/Release/s1lent-integration.exe` (or `build/s1lent-integration.exe` for a single-configuration generator). The program binds loopback UDP ports and exercises IPv4 DATA in both directions through Client → Node A → Node B → Server → Node B → Node A → Client, using fake IP interfaces instead of modifying host networking.

The client verifies the TLS server certificate and identity against a trusted PEM certificate. Over that TLS 1.3 channel it requests a configured route and session ID. Both endpoints derive a fresh session key with OpenSSL's TLS exporter before sending DATA.

## Local CLI demo

Start the server and two nodes in three PowerShell terminals from the repository root. The example route in `config/routes.example.conf` sends through ports 9001 and 9002 to server UDP port 9003. Create a local TLS certificate for the demo:

```powershell
$env:OPENSSL_CONF = 'C:\Program Files\Git\ucrt64\etc\ssl\openssl.cnf'
openssl req -x509 -newkey rsa:2048 -nodes -keyout build/tls-key.pem -out build/tls-cert.pem -days 30 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost'
```

Terminal 1 (server):

```powershell
.\build\Release\s1lent-server.exe .\config\routes.example.conf 127.0.0.1 9003 127.0.0.1 9004 .\build\tls-cert.pem .\build\tls-key.pem
```

Terminal 2 (Node A):

```powershell
.\build\Release\s1lent-node.exe .\config\routes.example.conf 0 127.0.0.1 9001 node-a
```

Terminal 3 (Node B):

```powershell
.\build\Release\s1lent-node.exe .\config\routes.example.conf 1 127.0.0.1 9002 node-b
```

In a fourth terminal, send a message. The handshake sets up the route and derives the session key before DATA:

```powershell
.\build\Release\s1lent-client.exe .\config\routes.example.conf 0.0.0.0 0 localhost 9004 .\build\tls-cert.pem auto 'hello S1lent'
```

The client prints `echo:hello S1lent`.

## Windows IP traffic through Wintun

Place the official `wintun.dll` beside the executables. Start the server with `--tun S1lent` and the client with `--tun S1lent`. Windows adapter addresses, routes, MTU, and forwarding are configured separately. The current S1lent packet limit is 1156 bytes per IP packet; larger packets require fragmentation, which is not implemented.

## Next

The next step is to strengthen session lifecycle handling and validate OS IP traffic through Wintun on a configured Windows host. Performance work comes after the end-to-end path is reliable. This project is experimental and makes no throughput or latency claims.
