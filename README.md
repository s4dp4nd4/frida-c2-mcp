# FridaC2MCP

A proof-of-concept, MCP server with streamable HTTP transport that exposes Frida's powerful dynamic instrumentation capabilities as a simple, remote server.

[![TLDR Featured](https://img.shields.io/badge/Featured%20in-TLDR%20InfoSec-blue)](https://tldr.tech/infosec/2026-01-30)

**This project is designed to run directly on a rooted Android device** (e.g., within Termux) and allow a remote client to analyze and manipulate running applications over the network. It acts as a bridge, turning Frida functions into tools that can be called via HTTP requests, with the goal of enabling automated, agent-based mobile security testing.

https://github.com/user-attachments/assets/7cee77c5-ed40-4797-b6b5-3edb5fdd03ce

## Core Functionality

- **Process & Application Management:** List installed applications, enumerate running processes, and get information about the foreground application.
- **Application Control:** Start and terminate applications by their identifier or PID.
- **Dynamic Instrumentation:** Create interactive sessions by attaching to running processes.
- **Remote Script Execution:** Execute custom Frida (JavaScript) scripts within an attached session. Scripts are bundled on-the-fly using `esbuild` to ensure compatibility with modern Frida versions. This supports both temporary scripts and persistent hooks (`keep_alive=True`).

## Intended Use Case

The primary goal of this project is to facilitate remote and automated mobile application security testing. By exposing Frida as an MCP server, a pentester or an automated agent (such as an LLM) can inspect and modify an application's behavior without needing a direct USB connection or local shell access after initial setup. The client does not need any Frida tooling installed as it is all contained on the target device.

A typical use case involves:
1.  Starting a target application on the device remotely.
2.  Attaching a Frida session to the application.
3.  Injecting a JavaScript hook to bypass security controls, such as the root detection check in `owasp.sat.agoat`.
4.  Observing the change in the application's behavior.

## Architecture & Design Rationale

The system operates on a client-server model with specific design choices to enable its unique, on-device execution environment.

-   **Server (`cli.py`):** A Python script using `FastMCP` and `asyncio`. This runs **on the Android device itself**, listens for HTTP requests, and translates them into Frida commands.

-   **Client:** Any HTTP client can interact with the server. The project was designed with tooling like `5ire` in mind, allowing generative AI agents to interact with the instrumented device.

-   **Streamable HTTP Transport:** The server uses a streamable HTTP transport instead of a simpler stdio-based one. This was a deliberate choice to allow for multiple, concurrent connections, paving the way for more complex Agent-to-Agent (A2A) communication scenarios between multiple devices.

-   **On-Device Script Bundling with `esbuild`:** Frida versions 17+ require JavaScript to be minified or bundled. As `frida-compile` proved difficult to run directly on Android, this project uses `esbuild` as a lightweight alternative. The server automatically handles the process of writing JS code to a temporary file, bundling it with `esbuild`, and loading the result into the target process.

-   **Manally Compiled Frida Version:** The project currently depends on manually compiling the latest Frida client on-device. This is due to unstable C-bindings in the frida-python library. The workaround is to manually hijack the internal toolchain associated with frida-core and supply Termux-native tooling.

---

## Roadmap & Progress

**Android**

- **Native tooling upgrade:** Since I have a manual build technique for Frida I can just drop `esbulid` and just install `frida-tools` over Frida so `frida-compile` can be used instead of `esbuild`, so planning on releasing that for a cleaner build. This way we can just call all our favorite frida tools on-device XD

**iOS**

- **iOS rootless jailbreak support:** I went on a truly unhinged and nightmarish foray into compiler hell, but I have a (mostly) working version that I tested on my rootless jailbroken iPhone X running iOS 16.7.12 **almost** ready for release! :3
- **Python3.12:** This will feature a custom-compiled Python 3.12, a version not even available yet via Procursus repo. It also includes a suite of custom-compiled Python packages patched specifically for rootless environments. This was necessary imo to bring the full power of  `fastmcp` to iOS.
- **Nodeless design:** Node.js is not necessary. Supports (only) ObjC for on-the-fly compilation.

## Acknowledgments
This project is a networked evolution of the original [FridaMCP](https://github.com/dnakov/frida-mcp) by Daniel Nakov. 
While the original project pioneered the use of Frida as an MCP server over stdio, **FridaC2MCP** adapts this concept for remote, multi-device C2 environments using Streamable HTTP and modern Frida 17 bundling.

---

### **⚠️ Disclaimer & Future Plans**

This is a rough draft and a proof-of-concept. It lacks proper session management, graceful error handling, and, most importantly, **any form of security**. All communication is unencrypted and unauthenticated. **Use at your own risk** and only in secure, isolated network environments.

Future plans include improving session management, implementing security measures, and potentially expanding support to iOS.
