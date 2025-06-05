# Sniffer-and-Spoofer

This project combines two key components: a **Sniffer** and a **Spoofer**, for analyzing and manipulating network traffic. It allows packet capturing, protocol inspection, and packet injection through a client-server architecture.

## Features

- **Packet Sniffing**: Capture and analyze live network packets.
- **Packet Spoofing**: Create and inject custom packets into the network.
- **Client-Server Communication**: Control sniffer and spoofer behavior remotely via a Python interface.
- **C and Python Integration**: Low-level packet processing in C with a high-level interface in Python.

## Project Structure

Sniffer-and-Spoofer/
├── .vscode/           # VSCode settings
├── pycache/       # Python cache
├── api.py             # API interface for control and communication
├── calculator.py      # Contains calculation logic (e.g. checksums, validations)
├── client.py          # Client application to send commands
├── server.py          # Server application to manage sniffer/spoofer
├── makefile           # Build file for compiling C components
├── sniffer.c/h        # C implementation of the sniffer
├── spoofer.c/h        # C implementation of the spoofer

## Requirements

- Python 3.6 or higher
- GCC or compatible C compiler
- Unix-based OS (Linux, macOS)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/Avichai-Mizrachi/Sniffer-and-Spoofer.git
cd Sniffer-and-Spoofer

2.	Compile the C components:

```bash
make
```

3.	Run the server:

```bash
python3 server.py
```

4.	Run the client:

```bash
python3 client.py
```

## Usage

Once the client and server are running, you can use the interface to:
	•	Start packet sniffing
	•	Analyze and log network protocols
	•	Send spoofed packets

⚠️ Warning: This tool is intended for educational and controlled testing purposes only. Unauthorized use may violate laws and regulations.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request with improvements or bug fixes.

## Project by

Avichai Mizrachi
