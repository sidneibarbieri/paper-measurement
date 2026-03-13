#!/usr/bin/env python3
"""
Caldera Command Executor

This script executes commands on Caldera agents and retrieves outputs
using the standard REST API.

Author: Created for Caldera automation
Date: 2026-02-13
"""
import sys
import json
import time
import base64
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    import config
except ImportError:
    print("❌ Could not import 'config' module.", file=sys.stderr)
    print("   Please ensure config.py exists with CALDERA_URL and CALDERA_API_KEY_RED", file=sys.stderr)
    sys.exit(1)

HEADERS = {
    "Content-Type": "application/json",
    "KEY": config.CALDERA_API_KEY_RED
}
BASE_URL = config.CALDERA_URL.rstrip("/")

# Hardcoded Manual Command ability ID
MANUAL_COMMAND_ABILITY_ID = "306a1842-1f49-4990-abba-6cc063c055c0"


class CalderaCommandExecutor:
    """
    Executor for running commands on Caldera agents with output retrieval.
    """

    def __init__(self, agent_paw: str = None):
        self.base_url = BASE_URL
        self.headers = HEADERS
        self.operation_id = None
        self.agent_paw = agent_paw
        self.quiet_mode = False

    def get_active_agents(self) -> List[Dict]:
        """Get all active agents from Caldera"""
        endpoint = f"{self.base_url}/api/v2/agents"

        try:
            resp = requests.get(endpoint, headers=self.headers)
            resp.raise_for_status()
            agents = resp.json()
            
            # Filter for active agents (alive and with valid last_seen)
            active_agents = []
            for agent in agents:
                # You might want to add additional filtering logic here
                # For example: check if agent is alive based on last_seen timestamp
                if agent.get('alive', False) or True:  # Adjust this logic as needed
                    active_agents.append(agent)
            
            return active_agents
        except requests.RequestException as e:
            print(f"❌ Failed to fetch agents: {e}", file=sys.stderr)
            return []

    def find_operation(self, operation_name: str) -> bool:
        """Find operation by name and store its ID"""
        endpoint = f"{self.base_url}/api/v2/operations"

        try:
            resp = requests.get(endpoint, headers=self.headers)
            resp.raise_for_status()
            operations = resp.json()

            for op in operations:
                if op.get("name") == operation_name:
                    self.operation_id = op.get("id")
                    if not self.quiet_mode:
                        print(f"✅ Found operation: {op.get('name')} (ID: {self.operation_id})", file=sys.stderr)
                        print(f"   State: {op.get('state')}", file=sys.stderr)
                    return True

            print(f"❌ No operation found with name: {operation_name}", file=sys.stderr)
            return False

        except requests.RequestException as e:
            print(f"❌ Failed to fetch operations: {e}", file=sys.stderr)
            return False

    def get_agent_info(self) -> Optional[Dict]:
        """Get agent information"""
        if not self.agent_paw:
            print("❌ No agent paw specified", file=sys.stderr)
            return None
            
        endpoint = f"{self.base_url}/api/v2/agents/{self.agent_paw}"

        try:
            resp = requests.get(endpoint, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
            return None
        except requests.RequestException:
            return None

    def decode_base64_output(self, encoded_data: str) -> str:
        """Decode base64 encoded output"""
        if not encoded_data:
            return ""

        try:
            # Try to decode as base64
            decoded = base64.b64decode(encoded_data).decode('utf-8', errors='ignore')
            return decoded
        except Exception as e:
            # If not valid base64 or decoding fails, return as is
            return encoded_data

    def extract_stdout_from_result(self, result_data: Any) -> str:
        """
        Extract stdout from the result data
        """
        try:
            # Case 1: The response has 'link' and 'result' fields
            if isinstance(result_data, dict):
                if 'result' in result_data:
                    result_field = result_data['result']

                    # Decode the base64 result field
                    if isinstance(result_field, str):
                        decoded = self.decode_base64_output(result_field)

                        # Parse the decoded JSON
                        try:
                            parsed = json.loads(decoded)

                            # Extract stdout from the parsed JSON
                            if isinstance(parsed, dict):
                                if 'stdout' in parsed:
                                    stdout = parsed['stdout']
                                    # Check if stdout is base64 encoded
                                    if isinstance(stdout, str):
                                        # Try to decode if it's base64
                                        try:
                                            if len(stdout) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in stdout):
                                                return self.decode_base64_output(stdout)
                                        except (ValueError, UnicodeDecodeError):
                                            pass
                                        return stdout
                                elif 'output' in parsed:
                                    return parsed['output']
                        except json.JSONDecodeError:
                            # If not JSON, return the decoded string
                            return decoded

            # Case 2: Direct stdout field
            elif isinstance(result_data, dict) and 'stdout' in result_data:
                stdout = result_data['stdout']
                if isinstance(stdout, str):
                    # Check if it's base64 encoded
                    try:
                        if len(stdout) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in stdout):
                            return self.decode_base64_output(stdout)
                    except (ValueError, UnicodeDecodeError):
                        pass
                    return stdout

            # Case 3: Direct output field
            elif isinstance(result_data, dict) and 'output' in result_data:
                output = result_data['output']
                if isinstance(output, str):
                    return output

            # Case 4: String result
            elif isinstance(result_data, str):
                # Try to decode if it's base64
                try:
                    if len(result_data) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in result_data):
                        decoded = self.decode_base64_output(result_data)
                        # Check if decoded is JSON
                        if decoded.strip().startswith('{') and decoded.strip().endswith('}'):
                            try:
                                parsed = json.loads(decoded)
                                if isinstance(parsed, dict) and 'stdout' in parsed:
                                    return parsed['stdout']
                            except (json.JSONDecodeError, ValueError):
                                pass
                        return decoded
                except (ValueError, UnicodeDecodeError):
                    pass
                return result_data

        except (KeyError, TypeError, ValueError):
            pass

        return "[No output]"

    def get_link_result(self, link_id: str, command: str) -> Optional[Dict]:
        """
        Get command output using the standard API endpoint:
        /api/v2/operations/{operation_id}/links/{link_id}/result

        Args:
            link_id: The link ID to get output for
            command: The original command that was executed

        Returns:
            Dict with extracted paw, command, and decoded result
        """
        if not self.operation_id:
            print("❌ No operation ID set", file=sys.stderr)
            return None

        endpoint = f"{self.base_url}/api/v2/operations/{self.operation_id}/links/{link_id}/result"

        try:
            resp = requests.get(endpoint, headers=self.headers)

            if resp.status_code == 200:
                result_data = resp.json()

                # Extract stdout from the result
                console_output = self.extract_stdout_from_result(result_data)

                # Create extracted result
                extracted = {
                    "paw": self.agent_paw,
                    "command": command,
                    "result": console_output
                }

                # In quiet mode, print ONLY the output to stdout (no prefixes)
                if self.quiet_mode:
                    if console_output and console_output != "[No output]":
                        print(console_output)
                    # Don't print anything for empty output in quiet mode
                else:
                    # Print with formatting to stderr for non-quiet mode
                    if console_output and console_output != "[No output]":
                        print(console_output, file=sys.stderr)
                    else:
                        print("[No output or empty result]", file=sys.stderr)

                return extracted
            else:
                if not self.quiet_mode:
                    print(f"⚠️  Failed to get link result: HTTP {resp.status_code}", file=sys.stderr)
                    if resp.text:
                        print(f"   Response: {resp.text}", file=sys.stderr)
                return None

        except requests.RequestException as e:
            if not self.quiet_mode:
                print(f"⚠️  Error getting link result: {e}", file=sys.stderr)
            return None

    def create_potential_link(self, command: str, executor: str = "sh") -> Optional[str]:
        """
        Create a potential link (scheduled command) for the agent to pick up.

        Args:
            command: Shell command to execute
            executor: Executor type (sh, psh, cmd)

        Returns:
            Link ID if successful, None otherwise
        """
        if not self.operation_id:
            print("❌ No operation ID set", file=sys.stderr)
            return None
            
        if not self.agent_paw:
            print("❌ No agent paw specified", file=sys.stderr)
            return None

        endpoint = f"{self.base_url}/api/v2/operations/{self.operation_id}/potential-links"

        # Get agent platform
        agent_info = self.get_agent_info()
        platform = agent_info.get('platform', 'linux') if agent_info else 'linux'

        # Create executor object with full structure
        executor_obj = {
            "name": executor,
            "platform": platform,
            "command": command + "\n",
            "code": None,
            "language": None,
            "build_target": None,
            "payloads": [],
            "uploads": [],
            "timeout": 60,
            "parsers": [],
            "cleanup": [],
            "variations": [],
            "additional_info": {}
        }

        # Create the payload
        payload = {
            "paw": self.agent_paw,
            "ability_id": MANUAL_COMMAND_ABILITY_ID,
            "executor": executor_obj,
            "command": command,
            "status": -3
        }

        try:
            resp = requests.post(endpoint, headers=self.headers, json=payload)

            if resp.status_code == 200:
                result = resp.json()

                if isinstance(result, list) and len(result) > 0:
                    link_id = result[0].get('id')
                elif isinstance(result, dict):
                    link_id = result.get('id')
                else:
                    link_id = "pending"

                if link_id:
                    if not self.quiet_mode:
                        print(f"✅ Command scheduled successfully", file=sys.stderr)
                        print(f"   Link ID: {link_id}", file=sys.stderr)
                    return link_id
            else:
                if not self.quiet_mode:
                    print(f"❌ Failed to create command: {resp.status_code}", file=sys.stderr)
                    print(f"   Response: {resp.text}", file=sys.stderr)
                return None

        except requests.RequestException as e:
            if not self.quiet_mode:
                print(f"❌ Error creating command: {e}", file=sys.stderr)
            return None

    def get_all_links(self) -> List[Dict]:
        """Get all links for the operation"""
        if not self.operation_id:
            return []

        endpoint = f"{self.base_url}/api/v2/operations/{self.operation_id}/links"

        try:
            resp = requests.get(endpoint, headers=self.headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            pass

        return []

    def find_link_by_command(self, command: str) -> Optional[Dict]:
        """Find a link that matches our command"""
        links = self.get_all_links()

        for link in links:
            if link.get('command') == command:
                return link

        return None

    def wait_for_execution(self, command: str, max_retries: int = 10800, delay: int = 2) -> Dict:
        """
        Wait for the agent to pick up and execute the command.

        Args:
            command: Command to wait for
            max_retries: Maximum polling attempts (10800 attempts * 2 seconds = 360 minutes = 6 hours)
            delay: Seconds between polls

        Returns:
            Dict with status and execution details
        """
        total_minutes = (max_retries * delay) / 60
        if not self.quiet_mode:
            print(f"\n⏳ Waiting for agent to execute command...", file=sys.stderr)
            print(f"   (Agent beacons every few seconds, this may take up to {int(total_minutes)} minutes)", file=sys.stderr)

        for attempt in range(max_retries):
            link = self.find_link_by_command(command)

            if link:
                status = link.get("status")

                if status == 0:  # Completed successfully
                    link_id = link.get("id")
                    facts = link.get("facts", [])

                    # Get output via standard API
                    output_data = self.get_link_result(link_id, command)

                    result = {
                        "status": "completed",
                        "link_id": link_id,
                        "pid": link.get("pid"),
                        "facts": facts,
                        "finish_time": link.get("finish"),
                        "host": link.get("host")
                    }

                    return result

                elif status in [-2, -3]:  # Pending/Queued
                    if not self.quiet_mode and attempt % 300 == 0:  # Print every 10 minutes
                        elapsed_minutes = (attempt * delay) / 60
                        print(f"   Status: Queued... ({elapsed_minutes:.1f} minutes elapsed)", file=sys.stderr)
                elif status == 1:  # Running
                    if not self.quiet_mode and attempt % 300 == 0:  # Print every 10 minutes
                        elapsed_minutes = (attempt * delay) / 60
                        print(f"   Status: Running... ({elapsed_minutes:.1f} minutes elapsed)", file=sys.stderr)
                elif status == -1:  # Failed
                    return {
                        "status": "failed",
                        "error": link.get("status_text", "Command failed"),
                        "link_id": link.get("id")
                    }
            else:
                if not self.quiet_mode and attempt % 300 == 0:  # Print every 10 minutes
                    elapsed_minutes = (attempt * delay) / 60
                    print(f"   Waiting for agent to pick up command... ({elapsed_minutes:.1f} minutes elapsed)", file=sys.stderr)

            time.sleep(delay)

        return {
            "status": "timeout",
            "error": f"Command did not complete within {int((max_retries * delay) / 60)} minutes"
        }

    def execute_command(self, command: str, executor: str = "sh") -> bool:
        """
        Main command execution function.

        Args:
            command: Shell command to execute
            executor: Executor type (sh, psh, cmd)

        Returns:
            True if command executed successfully, False otherwise
        """
        if not self.quiet_mode:
            print(f"\n🚀 Executing command: {command}", file=sys.stderr)
            print(f"   Executor: {executor}", file=sys.stderr)
            print(f"   Agent: {self.agent_paw}", file=sys.stderr)

        # Create potential link
        link_id = self.create_potential_link(command, executor)

        if not link_id:
            if not self.quiet_mode:
                print("\n❌ Failed to schedule command", file=sys.stderr)
            return False

        # Wait for execution
        result = self.wait_for_execution(command)

        return result.get("status") == "completed"


def select_agent_interactive(agents: List[Dict]) -> Optional[str]:
    """Interactive agent selection"""
    if not agents:
        print("❌ No active agents found", file=sys.stderr)
        return None
    
    print("\n📋 Available active agents:", file=sys.stderr)
    print("-" * 80, file=sys.stderr)
    
    for i, agent in enumerate(agents, 1):
        paw = agent.get('paw', 'Unknown')
        host = agent.get('host', 'Unknown')
        platform = agent.get('platform', 'Unknown')
        last_seen = agent.get('last_seen', 'Unknown')
        alive = agent.get('alive', False)
        
        status = "🟢 Alive" if alive else "⚪ Unknown"
        print(f"{i}. PAW: {paw}", file=sys.stderr)
        print(f"   Host: {host} | Platform: {platform}", file=sys.stderr)
        print(f"   Status: {status} | Last seen: {last_seen}", file=sys.stderr)
        print(file=sys.stderr)
    
    while True:
        try:
            choice = input("Select agent number (or enter PAW directly): ").strip()
            
            # Check if input is a number
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(agents):
                    return agents[idx].get('paw')
                else:
                    print(f"❌ Invalid selection. Please choose 1-{len(agents)}", file=sys.stderr)
            else:
                # Assume it's a PAW
                return choice
        except KeyboardInterrupt:
            print("\n❌ Selection cancelled", file=sys.stderr)
            return None
        except Exception as e:
            print(f"❌ Invalid input: {e}", file=sys.stderr)


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description="Execute commands on Caldera agents and display results",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("operation_name", help="Name of the Caldera operation")
    parser.add_argument("command", help="Command to execute")
    parser.add_argument("--executor", default="sh", choices=["sh", "psh", "cmd"],
                       help="Command executor (default: sh)")
    parser.add_argument("--agent", help="Agent PAW (if not provided, will select from active agents)")
    parser.add_argument("--timeout", type=int, default=360,
                       help="Timeout in minutes (default: 360 minutes = 6 hours)")

    args = parser.parse_args()

    # First, check if we have a single active agent (for quiet mode)
    temp_executor = CalderaCommandExecutor()
    active_agents = temp_executor.get_active_agents()
    
    # Determine if we should use quiet mode (exactly one agent and no agent specified)
    use_quiet_mode = len(active_agents) == 1 and not args.agent
    
    # Determine agent paw
    agent_paw = args.agent
    
    if not agent_paw:
        if use_quiet_mode:
            # Single agent - use it automatically in quiet mode
            agent_paw = active_agents[0].get('paw')
            # No output in quiet mode
        else:
            # Multiple agents or no agents - need to handle
            if not active_agents:
                print("❌ No active agents found in Caldera", file=sys.stderr)
                sys.exit(1)
            
            # Multiple agents - prompt for selection (always with output)
            print("\n🔍 No agent specified, fetching active agents...", file=sys.stderr)
            agent_paw = select_agent_interactive(active_agents)
            
            if not agent_paw:
                print("❌ No agent selected", file=sys.stderr)
                sys.exit(1)
            
            print(f"\n✅ Selected agent: {agent_paw}", file=sys.stderr)

    # Create executor with selected agent and quiet mode setting
    executor = CalderaCommandExecutor(agent_paw=agent_paw)
    executor.quiet_mode = use_quiet_mode

    # Find operation
    if not executor.find_operation(args.operation_name):
        sys.exit(1)

    # Get agent info (only in non-quiet mode)
    if not use_quiet_mode:
        agent_info = executor.get_agent_info()
        if agent_info:
            print(f"\n🤖 Agent: {agent_paw} on {agent_info.get('host')}", file=sys.stderr)

    # Execute command
    success = executor.execute_command(args.command, args.executor)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
