# README

This README provides information about the simple TCP client (`sclient.c`) and server (`sserver.c`) applications. These programs demonstrate basic TCP/IP communication between a client and a server in C language. The client sends a message to the server, and the server responds back after processing the message.

## Overview

The **Simple TCP Client** (`sclient.c`) reads a message from the standard input (stdin), sends it to a specified server, and then displays the server's response.

The **Simple TCP Server** (`sserver.c`) listens for connections on a specified port, reads the message sent by the client, processes it, and sends a response back.

## Compilation

Before running the applications, they need to be compiled. You will need a C compiler (e.g., `gcc`) installed on your system.

To compile the client:

```
make sclient
```

To compile the server:

```
make sserver
```

To compile or clean all the files:

```
make all(clean all)
```

## Usage

### Server

Run the server by specifying the port number on which it will listen for connections:

```
./sserver -p [port]
```

Replace `[port]` with the actual port number (e.g., `8080`).

### Client

Run the client by specifying the server IP and port number:

```
./sclient -p [port] -s [server-ip] < file-to-send.txt
```

Replace `[port]` with the server's port number and `[server-ip]` with the server's IP address.

## Features

- **Client:**
	- Connects to a server specified by IP and port.
	- Sends data read from file to the server.
	- Receives and displays the server's response.
	- Supports both IPv4 and IPv6 connections.
- **Server:**
	- Listens for connections on a specified port.
	- Accepts connections from clients.
	- Reads and processes received data.
	- Sends a response back to the client.

## Limitations

- The client and server are implemented for demonstration purposes and may not cover all edge cases.
- Error handling is basic, primarily for clarity and understanding.

## Example Session

1. Start the server:

	```
	./sserver -p 8080
	```

2. In a new terminal, start the client:

	```
	./sclient -p 8080 -s 127.0.0.1 < file-to-send.txt
	```

3. The server receives the message, processes it, and the client displays the response.

## Troubleshooting

- Ensure the server is running before starting the client.
- Check if the port number is available and not used by other applications.
- Verify that the server IP address and port number are correct in the client command.