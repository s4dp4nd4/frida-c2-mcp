Critical issues / Challenges / Research / Solutions
===================

MCP Transport to Streamable HTTP
---------------

* Challenge: A2A Framework will likely work better with streamable HTTP than stdio implementation , this way we can have multiple devices

  * In an A2A mcp tutorial here: https://github.com/Tsadoq/a2a-mcp-tutorial - "If you try to spawn multiple STDIO-based MCP servers, you will notice that they will not work at the same time. To solve this problem, we can use an SSE-based MCP server with some tricks."

  * SSE has shifted to streamable HTTP as seen here: https://brightdata.com/blog/ai/sse-vs-streamable-http

* Solution - Streamable HTTP was implemented

Running Frida _client_ on Android architecture
---------------
* Challenge: Compiling the frida proved to be difficult directly on Android devices

  * Used this as a reference but was not able to follow the flow properly - https://github.com/frida/frida/discussions/2411

  * `make` was failing to build. Essentially running into this issue here: https://github.com/frida/frida/issues/2864

* Solution - Hijacked the internal toolchain by swapping out broken binaries with Termux-native versions

Running Frida scripts with 17
--------------

* Challenge: Running scripts on Frida 17 has some level of requirement of frida-compile and minification, but frida-compile does not run and cannot install frida-compile through node

  * Java not defined is a known error here: https://github.com/frida/frida/issues/3473 , basically just need to minify the script

* Solution: Figured out that while frida-compile will not work, `esbuild` is good enough just to minify. Implemented a temporary file write from the users payload and added an import statement for java if one was not found. My logic is that folks will still attempt to use frida scripts compatible with 16 but not 17

Open issues
=================

5ire can't render frida scripts
---------

* When I ask Gemini to make a frida script for me instead of supplying one myself, it will not render. Not sure if a UI bug or a Gemini bug. However you can ask 5ire to call a tool with a script, and it won't have an issue calling the appropriate tool.

get_session_messages isn't working as expected
---------

* This is likely just a threading issue that needs to be reworked. In the meantime if you configure any scripts with console output, you can just change applications to termux and see the output to the terminal there.

Future plans
=================

* Looking into implementing the frida client on iOS, might run into same compiling issues. Will use [DVIA-v2](https://github.com/prateek147/DVIA-v2) for the target application.

* Need to implement session management

* Need to implement any level of security XD