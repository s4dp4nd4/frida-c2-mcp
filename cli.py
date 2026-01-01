import asyncio
from typing import Dict, Any, Optional, List
from pydantic import Field
import frida
from fastmcp import FastMCP
from threading import Lock
import tempfile
import os

mcp = FastMCP("FridaC2MCP", json_response=True, stateless_http=False)

# Globals for managing interactive sessions
_scripts = {}
_script_messages = {}
_message_queues = {}
global_persistent_scripts = {}

# --- Helper Functions ---

def _get_device_sync() -> frida.core.Device:
    """Blocking helper to get the device (run in thread)."""
    try:
        return frida.get_remote_device()
    except Exception as e:
        raise RuntimeError(f"Could not connect to remote Frida server: {e}")

async def _get_remote_device() -> frida.core.Device:
    """Async wrapper to get device without blocking the event loop."""
    return await asyncio.to_thread(_get_device_sync)

# --- Tools ---

@mcp.tool()
async def get_device_information() -> Dict[str, Any]:
    """Retrieves detailed system information for the remote device."""
    device = await _get_remote_device()

    try:
        params = await asyncio.to_thread(device.query_system_parameters)
        return params
    except Exception as e:
        raise RuntimeError(f"Failed to query system parameters: {e}")

@mcp.tool()
async def list_installed_applications() -> List[Dict[str, Any]]:
    """
    Lists all installed applications on the remote device.
    Returns a list of applications including their name, identifier, and PID if running.
    """
    device = await _get_remote_device()
    
    try:
        applications = await asyncio.to_thread(device.enumerate_applications)

        if not applications:
            return []
        
        return [
            {
             "pid": app.pid if app.pid != 0 else None,
             "name": app.name,
             "identifier": app.identifier
            }
            for app in sorted(applications, key=lambda app: app.name.lower())
        ]

    except Exception as e:
        raise RuntimeError(f"Failed to enumerate applications: {e}")

@mcp.tool()
async def enumerate_processes() -> List[Dict[str, Any]]:
    """
    Lists all running processes on the remote device.
    Returns a list of dictionaries containing the PID and process name.
    """
    device = await _get_remote_device()

    try:
        processes = await asyncio.to_thread(device.enumerate_processes)

        if not processes:
            return []
        
        return [
            {
                "pid": proc.pid,
                "name": proc.name
            }
            for proc in sorted(processes, key=lambda p: p.name.lower())
        ]
        
    except Exception as e:
        raise RuntimeError(f"Failed to enumerate processes: {e}")

@mcp.tool()
async def get_frontmost_application() -> Dict[str, Any]:
    """
    Gets information about the frontmost application on the remote device.

    Returns:
        A dictionary containing information about the frontmost application, or a
        message indicating that no application is in the foreground.
    """
    device = await _get_remote_device()

    try:
        app = await asyncio.to_thread(device.get_frontmost_application) 
    except Exception as e:
        raise RuntimeError(f"Failed to get the frontmost application: {e}")

    if app is None:
        return {"message": "No application is currently in the foreground."}

    return {
        "pid": app.pid,
        "name": app.name,
        "identifier": app.identifier
    }

@mcp.tool()
async def get_application_by_identifier(identifier: str) -> Dict[str, Any]:
    """
    Gets information about a specific application by its identifier.

    Args:
        identifier: The identifier of the application to look up.

    Returns:
        A string containing information about the application, or a message
        indicating that the application was not found.
    """
    device = await _get_remote_device()

    try:
        apps = await asyncio.to_thread(device.enumerate_applications)
        target = next(
            (a for a in apps if a.identifier.lower() == identifier.lower()
             or a.name.lower() == identifier.lower()),
            None
        )

        if not target:
            return {"found": False, "error": f"Application '{identifier}' not found."}
        
        return {
            "pid": target.pid if target.pid != 0 else None,
            "name": target.name,
            "identifier": target.identifier,
            "found": True
        }
        
    except frida.ProcessNotFoundError:
        return {"error": f"Application '{identifier}' not found."}
    except Exception as e:
        raise RuntimeError(f"An error occurred while getting the application: {e}")

@mcp.tool()
async def start_application(
    program: str = Field(description="The program/bundle identifier to spawn."),
    args: Optional[List[str]] = Field(default=None, description="Arguments.")
) -> Dict[str, Any]:
    """Starts a new application."""
    device = await _get_remote_device()
    try:
        pid = await asyncio.to_thread(device.spawn, program, args=args or [])
        await asyncio.to_thread(device.resume, pid)
        return {"pid": pid}
    except frida.ProcessNotFoundError:
        raise ValueError(f"Program '{program}' not found.")
    except Exception as e:
        raise RuntimeError(f"Failed to spawn '{program}': {e}")
    
@mcp.tool()
async def kill_process(pid: int) -> Dict[str, Any]:
    """Terminates a process."""
    device = await _get_remote_device()
    try:
        await asyncio.to_thread(device.kill, pid)
        return {"success": True, "message": f"Process {pid} terminated."}
    except Exception as e:
        raise RuntimeError(f"Failed to kill process {pid}: {e}")

@mcp.tool()
async def create_interactive_session(
    process_id: int = Field(description="The ID of the process to attach to.")
) -> Dict[str, Any]:
    """Create an interactive session."""
    try:
        device = await _get_remote_device()
        
        # Attach blocking call in thread
        session = await asyncio.to_thread(device.attach, process_id)
        
        # Use simple ID generation
        import time
        session_id = f"session_{process_id}_{int(time.time())}"
        
        _scripts[session_id] = session
        _script_messages[session_id] = []
        global_persistent_scripts[session_id] = []
        
        return {
            "status": "success",
            "session_id": session_id,
            "message": f"Session created for PID {process_id}."
        }
    except Exception as e:
        raise RuntimeError(f"Failed to create session: {e}")
    
@mcp.tool()
async def execute_in_session(
    session_id: str,
    javascript_code: str,
    keep_alive: bool = Field(default=False, description="Keep script loaded for hooks/callbacks.")
) -> Dict[str, Any]:
    """
    Execute JS in session. Compiles with esbuild before execution.
    Crucially: If you are hooking a function, you MUST set keep_alive=True.
    """
    if session_id not in _scripts:
        raise ValueError(f"Session {session_id} not found.")
    
    session = _scripts[session_id]
    if session.is_detached:
        raise frida.InvalidOperationError("Session is detached.")
    
    wrapped_code = f"""
    import Java from 'frida-java-bridge';
    'use strict';
    Java.perform({{
        onComplete: function() {{
            send({{ 'type': 'agent:ready' }}); // Signal that Java env is ready
            try {{
                var result = (function() {{
                    {javascript_code}
                }})();
                send({{ 
                    'type': 'agent:result', 
                    'status': 'success',
                    'result': result !== undefined ? String(result) : 'Script executed (no direct return value).',
                }});
            }} catch (e) {{
                send({{ 
                    'type': 'agent:result',
                    'status': 'error',
                    'error': {{ 'message': e.message, 'stack': e.stack }}
                }});
            }}
        }},
        onError: function(error) {{
             send({{ 
                'type': 'agent:result', // Send result on error too
                'status': 'error',
                'error': {{ 'message': "Java.perform error: " + error.message, 'stack': error.stack }}
            }});
        }}
    }});
    """

    if keep_alive:
        uncompiled_code = javascript_code
    else:
        uncompiled_code = wrapped_code

    # --- ESBuild Compilation Step ---
    compiled_code = ""
    # Use a unique name for temp files
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.js', dir="/data/data/com.termux/files/home",encoding='utf-8') as infile:
        infile_path = infile.name
        outfile_path = infile_path.replace('.js', '.compiled.js')

        try:
            # Ensure import exists
            if "frida-java-bridge" not in uncompiled_code:
                uncompiled_code = f"import Java from 'frida-java-bridge';\n{uncompiled_code}"
            
            infile.write(uncompiled_code)
            infile.close()
            
            command = [
                'esbuild', infile_path, '--bundle', '--minify', 
                f'--outfile={outfile_path}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise RuntimeError(f"esbuild failed: {stderr.decode()}")

            with open(outfile_path, 'r', encoding='utf-8') as f:
                compiled_code = f.read()

        finally:
            if os.path.exists(infile_path): os.remove(infile_path)
            if os.path.exists(outfile_path): os.remove(outfile_path)
    
    if not compiled_code:
        raise RuntimeError("Compilation produced an empty script.")

    loop = asyncio.get_running_loop()
    result_future = loop.create_future()

    def on_message(message, data):
        payload = message.get('payload', {{}})
        msg_type = payload.get('type')

        if message.get('type') == 'error':
            # This is a script compilation error
            if not result_future.done():
                result_future.set_exception(RuntimeError(message['description']))
            return
        
        if msg_type == 'agent:ready':
            if not result_future.done():
                loop.call_soon_threadsafe(result_future.set_result, payload)
        
        else: # Handle other messages like console.log, send(), etc.
             if session_id in _script_messages:
                _script_messages[session_id].append({{"type": message["type"], "payload": payload}})


    try:
        def sync_load_script():
            script = session.create_script(compiled_code)
            script.on("message", on_message)
            script.load()
            return script
        
        script = await asyncio.to_thread(sync_load_script)

        if keep_alive:
            global_persistent_scripts[session_id].append(script)

        if keep_alive:
            return {
                "status": "success",
                "message": "Persistent script loaded. Hooks are active if the script runs correctly.",
                "script_unloaded": False
            }

        # Wait for a non-persistent script to finish
        receipt = await asyncio.wait_for(result_future, timeout=10.0)

        result_data = {
            "status": receipt.get("status", "error"),
            "script_unloaded": not keep_alive
        }
        if receipt.get("status") == "success":
            result_data["result"] = receipt.get("result")
        else:
            result_data["error_details"] = receipt.get("error")
        
        return result_data

    except asyncio.TimeoutError:
        return {
            "status": "timeout",
            "message": "Timed out waiting for script result. The script may have hung.",
            "script_unloaded": not keep_alive
        }
    except Exception as e:
         return {"status": "error", "message": f"Failed to execute script: {{e}}"}

    finally:
        # Cleanup if not keeping alive and script was created
        if not keep_alive and 'script' in locals() and script:
            try:
                await asyncio.to_thread(script.unload)
            except:
                pass # Ignore unload errors

@mcp.tool()
async def get_session_messages(session_id: str) -> Dict[str, Any]:
    """Get queued messages."""
    if session_id not in _script_messages:
        raise ValueError("Session not found.")
    
    msgs = list(_script_messages[session_id])
    _script_messages[session_id].clear()
    return {"messages": msgs}

async def main():
    await mcp.run_http_async(host="0.0.0.0",transport='streamable-http',port=6767)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
