# Project Motivation

This is part of a greater idea to automate mobile pentesting with multiple agents that communicate over a protocol like A2A. This is a rough draft version where not all the tooling may work. It is possible to use stdio versions of this mcp server to make setup easier, but the intent of this is to have completely isolated devices that can cross-communicate on a network. **Use at your own risk.**

# Objective

- With a rooted Android device, install AndroGoat
- Navigate to the Root Detection challenge
- Prove that the "Device is rooted." message appears
- Run the MCP server on the Android device
- Connect to the MCP server with 5ire
- Use Gemini to open AndroGoat, create an interactive session with that launched application, write a persistent script and launch that script within the session
- Show that while the script is running in the background, when the user attempts the Root Detection challenge, the message "Device is not rooted." appears
- Kill the application

# Happy Path

This is the conversation that I had with Gemini 2.5 Flash

User:
```
open owasp.sat.agoat
```

Gemini:
```
The application owasp.sat.agoat has been started with process ID (PID) 22153.
```

User:
```
create an interactive session with that new process
```

Gemini:
```
An interactive session has been created for process ID 22153. The session ID is session_22153_1766192976.
```

User:
```
can you generate frida code to intercept a method called isRooted1 in the class owasp.sat.agoat.RootDetectionActivity
```

Gemini:
```
The Frida script has been loaded into the application process.

The script attempts to:

1. Locate the class owasp.sat.agoat.RootDetectionActivity.
2. Hook the method isRooted1.
3. Implement a bypass that logs the call and always returns false (to simulate a non-rooted device), effectively defeating this specific root detection check.

The hooks are now active for the owasp.sat.agoat application.
```

**If this doesn't work, try just pasting in the contents of test-frida-script.js and say run this in the current session and set keep_alive to true.**

**At this point you should be able to hit the "CHECK ROOT" button and see "Device is not rooted."**

User: 
```
can you kill the application that we launched
```

Gemini:
```
The process with PID 22153 (owasp.sat.agoat) has been successfully terminated.
```

# !!!KNOWN ISSUES!!!

- Latest version of the frida client is at the mercy of the termux root repo currently (12/19/25), which is 17.2.14
- Different AI models will have varied success on invoking the correct tool
- The 0.15.2 5ire release might break AI invocation, it's better to just [manually run the project with node](https://github.com/nanbingxyz/5ire/blob/main/DEVELOPMENT.md)
- Session management is not implemented, so if you kill a process there will be a dangling session and there is no way to list interactive sessions
- Tool prompts need to be reworked to help the agents pick the tool more accurately
- No graceful shutdown on the server
- The default root detection mechanism in AndroGoat does not detect the latest magisk jailbreaks because the `su` binary is placed in an unexpected location, so the source code for AndroGoat needs to be modified to uncomment out the logic for `isRooted1`
- get_session_messages isn't working as expected
- **Security in general is not implemented.** Your messages can be sniffed and they do not require authorization. **Use at your own risk.**

# General Setup Guide

This setup is pretty tedious as of now, there's kind of some painful restrictions from running the client on the device in addition to the server.

# Workstation Requirements

- Install [5ire](https://github.com/nanbingxyz/5ire)

  - **NOTE:** 0.15.2 release breaks Gemini invocation, at least for Windows. Run as a node project by following [this guide](https://github.com/nanbingxyz/5ire/blob/main/DEVELOPMENT.md). But be advised of two changes: node should be `22.19.0` and the new run command is `npm run dev -- --no-sandbox --disable-gpu`

  - Add the a tool config similar to the following: 

  ```
  {
  "name": "fridaMCP",
  "key": "frida",
  "url": "http://<phone_ip>:6767/mcp",
  "approvalPolicy": "always"
  }
  ```

- If you're used to a different client like `gemini-cli` or Claude Desktop, this _should_ be compatible with it

## Tested on

- Used 5ire with Gemini 2.5 Flash as the provider
- Used Pixel 9 running Android 16 API 36
- Used Magisk 30.4
- Used Frida 17.2.14

# Device Requirements

- A rooted Android device

  - Take a look at the process with [Magisk](https://github.com/topjohnwu/Magisk)

  - You can use an emulator, but a physical device is cooler :3 also with the emulator the networking isn't immediately obvious to setup, you'll have to use adb port forwarding or a non-standard network bridge in whatever emulator you're using

  - Unless you're dealing with sensitive data on the device just set Magisk to auto approve any superuser request

- Install AndroGoat

  - Just as an example we'll take a look at [AndroGoat](https://github.com/satishpatnayak/AndroGoat) . 

  - **NOTE**: For my device, Magisk had the `su` binary at `/system_ext/bin/su`, so this did not flag the root normally. In order to fix this you can change the logic `if(isRooted())// || isRooted1())` --> `if(isRooted() || isRooted1())` or just add wherever your su binary is in the `isRooted` array.

- A Frida server

  - Just use the [Frida Magisk module](https://github.com/ViRb3/magisk-frida/releases/tag/17.2.14-1). Make sure to grab the 17.2.14 version to match with the """latest""" frida client that we'll be interfacing with later

- Install termux

  - Use the [GitHub version of termux](https://github.com/termux/termux-app)

- Inside of termux install the root repo 

  - `pkg install root-repo`

- Inside of termux install all the packages (I might be missing stuff here)

  - The following should install necessary build tools: `pkg install python clang gcc rust nodejs` 

  - Do NOT install frida with pip -- it will fail cuz of the C bindings. Instead install via pkg (AFTER previous step) `pkg install frida frida-dev frida-python` as of 12/19/25 latest version is Frida 17.2.14 .

- Setup termux environment

  - Place `cli.py` in your home directory which should be `/data/data/com.termux/files/home` 

  - Inside of the home folder `/data/data/com.termux/files/home`, install node dependencies `npm install buffer frida-java-bridge process`. This is needed for Frida 17 because you need to compile (in our case bundle and transpile) javascript code in order for it to run. This is due to the script's design of using temporary files inside of `/data/data/com.termux/files/usr/tmp` to handle bundling and transpiling. By hardcoding the path to home instead of using the default temp directory, we ensure the node_modules are persistent and reachable by esbuild. The process is: write temp file -> bundle/transpile -> pass "compiled" logic to the rest of the script.

  - Install `esbuild` globally, this is what we'll use to bundle and transpile scripts instead of `frida-compile` because `frida-compile` has trouble running on Android. Can install with `npm` but can also install via `pkg install esbuild`.

- Install python dependencies - still working on requirements.txt

  - `pip install fastmcp pydantic`

  - **WARNING** Do not run `pip install frida`, because it will break. Only use `pkg install frida-python` as mentioned above

- Install your target application. As a PoC I used [AndroGoat](https://github.com/satishpatnayak/AndroGoat)