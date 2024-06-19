# Pipe Dreams R Us

## Project Overview

Pipe Dreams R Us is a proof of concept project designed to demonstrate the feasibility of communication to and from a DLL injected into a target process. The primary objective is to obscure potentially malicious activities of the main program by utilizing inter-process communication (IPC) via named pipes. The injected DLL establishes a pipe server within the target process, allowing external clients to interact with the process without directly modifying its memory or triggering security alarms.

## Features

- Injects a DLL into a specified target process ID.
- The injected DLL starts a named pipe server and listens for incoming connections.
- Allows bidirectional communication between the client and the DLL via byte arrays.
- Facilitates controlled interactions with the target process while maintaining a "clean" appearance from the client's perspective.

## Usage

### Prerequisites

- Windows operating system (due to DLL injection and named pipe usage).
- Visual Studio for compiling the project (if compiling from source).

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/yourusername/pipe-dreams-r-us.git
   cd pipe-dreams-r-us
