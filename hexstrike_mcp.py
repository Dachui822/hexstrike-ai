#!/usr/bin/env python3
"""
HexStrike AI MCP Client - Enhanced AI Agent Communication Interface

🚀 Bug Bounty | CTF | Red Team | Security Research

FIXES (v6.1):
✅ Added async task polling for long-running scans
✅ Progress feedback during tool execution
✅ Timeout-resistant with automatic retry
✅ Streaming status updates via logger
✅ Task ID tracking for resumable scans

Architecture: MCP Client for AI agent communication with HexStrike server
Framework: FastMCP integration for tool orchestration
"""

import sys
import os
import argparse
import logging
import time
import json
import threading
from typing import Dict, Any, Optional
import requests
from datetime import datetime

from mcp.server.fastmcp import FastMCP

# ============================================================================
# ENHANCED COLOR SYSTEM
# ============================================================================

class HexStrikeColors:
    """Enhanced color palette matching the server's ModernVisualEngine.COLORS"""

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    ROSE_RED = '\033[38;5;167m'
    BURGUNDY = '\033[38;5;52m'
    SCARLET = '\033[38;5;197m'
    RUBY = '\033[38;5;161m'

    HIGHLIGHT_RED = '\033[48;5;196m\033[38;5;15m'
    HIGHLIGHT_YELLOW = '\033[48;5;226m\033[38;5;16m'
    HIGHLIGHT_GREEN = '\033[48;5;46m\033[38;5;16m'
    HIGHLIGHT_BLUE = '\033[48;5;51m\033[38;5;16m'
    HIGHLIGHT_PURPLE = '\033[48;5;129m\033[38;5;15m'

    SUCCESS = '\033[38;5;46m'
    WARNING = '\033[38;5;208m'
    ERROR = '\033[38;5;196m'
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'
    INFO = '\033[38;5;51m'
    DEBUG = '\033[38;5;240m'

    VULN_CRITICAL = '\033[48;5;124m\033[38;5;15m\033[1m'
    VULN_HIGH = '\033[38;5;196m\033[1m'
    VULN_MEDIUM = '\033[38;5;208m\033[1m'
    VULN_LOW = '\033[38;5;226m'
    VULN_INFO = '\033[38;5;51m'

    TOOL_RUNNING = '\033[38;5;46m\033[5m'
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'
    TOOL_FAILED = '\033[38;5;196m\033[1m'
    TOOL_TIMEOUT = '\033[38;5;208m\033[1m'
    TOOL_RECOVERY = '\033[38;5;129m\033[1m'

Colors = HexStrikeColors

# ============================================================================
# ENHANCED LOGGING WITH PROGRESS TRACKING
# ============================================================================

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with colors and emojis for MCP client"""

    COLORS = {
        'DEBUG': HexStrikeColors.DEBUG,
        'INFO': HexStrikeColors.SUCCESS,
        'WARNING': HexStrikeColors.WARNING,
        'ERROR': HexStrikeColors.ERROR,
        'CRITICAL': HexStrikeColors.CRITICAL
    }

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '✅',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, HexStrikeColors.BRIGHT_WHITE)
        record.msg = f"{color}{emoji} {record.msg}{HexStrikeColors.RESET}"
        return super().format(record)

logging.basicConfig(
    level=logging.INFO,
    format="[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stderr)]
)

for handler in logging.getLogger().handlers:
    handler.setFormatter(ColoredFormatter(
        "[🔥 HexStrike MCP] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

DEFAULT_HEXSTRIKE_SERVER = "https://hestrike-mcp.mty.chinamcloud.com"
DEFAULT_REQUEST_TIMEOUT = 300
MAX_RETRIES = 3

# NEW: Async polling configuration
POLL_INTERVAL_SECONDS = 5       # Check task status every 5 seconds
PROGRESS_LOG_INTERVAL = 30      # Log progress summary every 30 seconds
MAX_TASK_WAIT_SECONDS = 3600    # Maximum wait time for long scans (1 hour)

# ============================================================================
# TASK STATE TRACKER
# ============================================================================

class TaskTracker:
    """Tracks running tasks and provides progress feedback"""

    def __init__(self):
        self.active_tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def register_task(self, task_id: str, tool_name: str, target: str):
        with self._lock:
            self.active_tasks[task_id] = {
                "tool": tool_name,
                "target": target,
                "start_time": time.time(),
                "status": "running",
                "last_progress": None,
                "poll_count": 0
            }

    def update_progress(self, task_id: str, progress: Dict[str, Any]):
        with self._lock:
            if task_id in self.active_tasks:
                self.active_tasks[task_id]["last_progress"] = progress
                self.active_tasks[task_id]["poll_count"] += 1

    def complete_task(self, task_id: str, success: bool = True):
        with self._lock:
            if task_id in self.active_tasks:
                self.active_tasks[task_id]["status"] = "completed" if success else "failed"

    def get_task_info(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self.active_tasks.get(task_id)

# Global task tracker
task_tracker = TaskTracker()

# ============================================================================
# ENHANCED HEXSTRIKE CLIENT WITH ASYNC POLLING
# ============================================================================

class HexStrikeClient:
    """Enhanced client with async task polling and progress feedback"""

    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

        connected = False
        for i in range(MAX_RETRIES):
            try:
                logger.info(f"🔗 Attempting to connect to HexStrike AI API at {server_url} (attempt {i+1}/{MAX_RETRIES})")
                try:
                    test_response = self.session.get(f"{self.server_url}/health", timeout=5)
                    test_response.raise_for_status()
                    health_check = test_response.json()
                    connected = True
                    logger.info(f"🎯 Successfully connected to HexStrike AI API Server at {server_url}")
                    logger.info(f"🏥 Server health status: {health_check.get('status', 'unknown')}")
                    logger.info(f"📊 Server version: {health_check.get('version', 'unknown')}")
                    break
                except requests.exceptions.ConnectionError:
                    logger.warning(f"🔌 Connection refused to {server_url}. Make sure the HexStrike AI server is running.")
                    time.sleep(2)
                except Exception as e:
                    logger.warning(f"⚠️  Connection test failed: {str(e)}")
                    time.sleep(2)
            except Exception as e:
                logger.warning(f"❌ Connection attempt {i+1} failed: {str(e)}")
                time.sleep(2)

        if not connected:
            error_msg = f"Failed to establish connection to HexStrike AI API Server at {server_url} after {MAX_RETRIES} attempts"
            logger.error(error_msg)

    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if params is None:
            params = {}
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"📡 GET {url} with params: {params}")
            response = self.session.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        url = f"{self.server_url}/{endpoint}"
        try:
            logger.debug(f"📡 POST {url} with data: {json_data}")
            response = self.session.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"🚫 Request failed: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"💥 Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    # ========================================================================
    # NEW: ASYNC TASK EXECUTION WITH PROGRESS POLLING
    # ========================================================================

    def submit_async_task(self, endpoint: str, json_data: Dict[str, Any], tool_name: str, target: str) -> Dict[str, Any]:
        """
        Submit a long-running task and wait for completion.

        FIX (2026-05-22 v6.3): Block until task completes.
        - Submit with short timeout (5s)
        - If server returns task_id: poll until complete
        - If server times out: find running task and poll until complete
        - Always return final scan result, never intermediate status
        """

        url = f"{self.server_url}/{endpoint}"
        json_data["async"] = True

        logger.info(f"{HexStrikeColors.FIRE_RED}🚀 Submitting async {tool_name} scan: {target}{HexStrikeColors.RESET}")

        try:
            submit_response = self.session.post(url, json=json_data, timeout=5)
            submit_response.raise_for_status()
            submit_result = submit_response.json()
        except requests.exceptions.Timeout:
            logger.warning(f"⏱️ Server executing, disconnecting quickly, polling for result...")
            task_id = self._find_running_task(tool_name, target)
            if task_id:
                task_tracker.register_task(task_id, tool_name, target)
                return self._poll_task_until_complete(task_id, tool_name, target, endpoint, json_data)
            return {
                "success": False,
                "error": "Server executing, no running task found after timeout",
                "tool": tool_name,
                "target": target
            }
        except Exception as e:
            logger.warning(f"⚠️ Submission error: {str(e)}")
            task_id = self._find_running_task(tool_name, target)
            if task_id:
                task_tracker.register_task(task_id, tool_name, target)
                return self._poll_task_until_complete(task_id, tool_name, target, endpoint, json_data)
            return {
                "success": False,
                "error": f"Submission failed: {str(e)}",
                "tool": tool_name,
                "target": target
            }

        # Check if server returned async task_id
        task_id = submit_result.get("task_id")
        if task_id:
            task_status = submit_result.get("status", "queued")
            task_tracker.register_task(task_id, tool_name, target)
            logger.info(f"{HexStrikeColors.NEON_BLUE}📋 Task ID: {task_id}{HexStrikeColors.RESET}")
            return self._poll_task_until_complete(task_id, tool_name, target, endpoint, json_data)

        # Server returned synchronous result
        logger.info(f"ℹ️ Server returned synchronous result")
        return submit_result


    def _poll_task_until_complete(self, task_id, tool_name, target, endpoint, json_data) -> Dict[str, Any]:
        """Poll server-side task status until completion. Returns final result."""
        start_time = time.time()
        last_log_time = time.time()

        while True:
            elapsed = time.time() - start_time

            # Check timeout
            if elapsed > MAX_TASK_WAIT_SECONDS:
                logger.error(f"{HexStrikeColors.ERROR}❌ Task {task_id} timed out after {elapsed:.0f}s{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=False)
                return {
                    "success": False,
                    "error": f"Task timed out after {elapsed:.0f}s",
                    "task_id": task_id,
                    "timeout": True
                }

            # Poll for status
            try:
                status_response = self.session.get(
                    f"{self.server_url}/api/tasks/{task_id}",
                    timeout=10
                )
                status_response.raise_for_status()
                status_data = status_response.json()
            except Exception as e:
                logger.warning(f"⚠️  Poll failed: {str(e)}")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            task_status = status_data.get("status", "unknown")
            progress = status_data.get("progress", {})
            message = status_data.get("message", "")

            # Update tracker
            task_tracker.update_progress(task_id, {
                "status": task_status,
                "progress": progress,
                "message": message,
                "elapsed": elapsed
            })

            # Log progress periodically
            if time.time() - last_log_time >= PROGRESS_LOG_INTERVAL:
                elapsed_min = elapsed / 60
                progress_pct = progress.get("percentage", "N/A") if isinstance(progress, dict) else "N/A"
                current_step = progress.get("current_step", "N/A") if isinstance(progress, dict) else "N/A"
                logger.info(
                    f"{HexStrikeColors.INFO}⏳ [{tool_name}] {elapsed_min:.1f}min elapsed | "
                    f"Progress: {progress_pct}% | Step: {current_step} | "
                    f"Status: {task_status}{HexStrikeColors.RESET}"
                )
                last_log_time = time.time()

            # Check completion
            if task_status in ("completed", "success", "done"):
                elapsed_min = elapsed / 60
                logger.info(f"{HexStrikeColors.SUCCESS}✅ Task {task_id} completed in {elapsed_min:.1f}min{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=True)
                return status_data

            elif task_status in ("failed", "error", "cancelled"):
                error_msg = status_data.get("error", "Unknown error")
                logger.error(f"{HexStrikeColors.ERROR}❌ Task {task_id} failed: {error_msg}{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=False)
                return status_data

            # Wait before next poll
            time.sleep(POLL_INTERVAL_SECONDS)

    def _poll_task_until_complete(self, task_id, tool_name, target, endpoint, json_data) -> Dict[str, Any]:
        """Poll server-side task status until completion. Returns final result."""
        start_time = time.time()
        last_log_time = time.time()

        logger.info(f"{HexStrikeColors.NEON_BLUE}⏳ Polling for progress (interval: {POLL_INTERVAL_SECONDS}s)...{HexStrikeColors.RESET}")

        while True:
            elapsed = time.time() - start_time

            # Check timeout
            if elapsed > MAX_TASK_WAIT_SECONDS:
                logger.error(f"{HexStrikeColors.ERROR}❌ Task {task_id} timed out after {elapsed:.0f}s{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=False)
                return {
                    "success": False,
                    "error": f"Task timed out after {elapsed:.0f}s",
                    "task_id": task_id,
                    "timeout": True,
                    "resume_hint": {
                        "endpoint": endpoint,
                        "task_id": task_id,
                        "json_data": json_data
                    }
                }

            # Poll for status
            try:
                status_response = self.session.get(
                    f"{self.server_url}/api/tasks/{task_id}",
                    timeout=10
                )
                status_response.raise_for_status()
                status_data = status_response.json()
            except Exception as e:
                logger.warning(f"⚠️  Poll failed: {str(e)}")
                time.sleep(POLL_INTERVAL_SECONDS)
                continue

            task_status = status_data.get("status", "unknown")
            progress = status_data.get("progress", {})
            message = status_data.get("message", "")

            # Update tracker
            task_tracker.update_progress(task_id, {
                "status": task_status,
                "progress": progress,
                "message": message,
                "elapsed": elapsed
            })

            # Log progress periodically
            if time.time() - last_log_time >= PROGRESS_LOG_INTERVAL:
                elapsed_min = elapsed / 60
                progress_pct = progress.get("percentage", "N/A") if isinstance(progress, dict) else "N/A"
                current_step = progress.get("current_step", "N/A") if isinstance(progress, dict) else "N/A"
                logger.info(
                    f"{HexStrikeColors.INFO}⏳ [{tool_name}] {elapsed_min:.1f}min elapsed | "
                    f"Progress: {progress_pct}% | Step: {current_step} | "
                    f"Status: {task_status}{HexStrikeColors.RESET}"
                )
                last_log_time = time.time()

            # Check completion
            if task_status in ("completed", "success", "done"):
                elapsed_min = elapsed / 60
                logger.info(f"{HexStrikeColors.SUCCESS}✅ Task {task_id} completed in {elapsed_min:.1f}min{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=True)
                return status_data

            elif task_status in ("failed", "error", "cancelled"):
                error_msg = status_data.get("error", "Unknown error")
                logger.error(f"{HexStrikeColors.ERROR}❌ Task {task_id} failed: {error_msg}{HexStrikeColors.RESET}")
                task_tracker.complete_task(task_id, success=False)
                return status_data

            # Wait before next poll
            time.sleep(POLL_INTERVAL_SECONDS)

    def execute_command(self, command: str, use_cache: bool = True) -> Dict[str, Any]:
        return self.safe_post("api/command", {"command": command, "use_cache": use_cache})

    def check_health(self) -> Dict[str, Any]:
        return self.safe_get("health")

    def list_active_tasks(self) -> Dict[str, Any]:
        """List all active tasks on the server"""
        return self.safe_get("api/tasks")

    def _find_running_task(self, tool_name: str, target: str) -> Optional[str]:
        """
        Find a running task on the server by tool_name and target.
        Returns task_id if found, None otherwise.
        """
        try:
            result = self.list_active_tasks()
            if not result.get("success"):
                return None
            # Server returns dict like {"tasks": [...], "count": N}
            tasks = result.get("tasks", [])
            for task in tasks:
                if task.get("tool") == tool_name and task.get("target") == target:
                    status = task.get("status", "")
                    if status in ("running", "queued", "executing"):
                        return task.get("task_id") or task.get("id")
        except Exception:
            pass
        return None

    def resume_task(self, task_id: str) -> Dict[str, Any]:
        """Resume a timed-out or interrupted task"""
        return self.safe_post(f"api/tasks/{task_id}/resume", {})

# ============================================================================
# PROGRESS-AWARE TOOL WRAPPER
# ============================================================================

def create_progress_aware_tool(hexstrike_client, endpoint: str, tool_name: str, target_param: str = "target"):
    """
    Factory function to create tools that support async execution with progress feedback.

    Usage:
        Instead of: result = hexstrike_client.safe_post("api/tools/nmap", data)
        Use:        result = hexstrike_client.submit_async_task("api/tools/nmap", data, "nmap", target)
    """
    def wrapper(data: Dict[str, Any]) -> Dict[str, Any]:
        target = data.get(target_param, data.get("url", data.get("domain", "unknown")))
        return hexstrike_client.submit_async_task(endpoint, data, tool_name, target)
    return wrapper

# ============================================================================
# MCP SERVER SETUP (with enhanced progress-aware tools)
# ============================================================================

def setup_mcp_server(hexstrike_client: HexStrikeClient) -> FastMCP:
    """Set up the MCP server with progress-aware tool functions"""

    mcp = FastMCP("hexstrike-ai-mcp", host="127.0.0.1", port=8000)

    # ========================================================================
    # CORE NETWORK SCANNING TOOLS (progress-aware)
    # ========================================================================

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Execute an enhanced Nmap scan against a target with progress feedback."""
        import time
        import subprocess
        
        start = time.time()
        logger.info(f"{HexStrikeColors.FIRE_RED}🔍 Initiating Nmap scan: {target}{HexStrikeColors.RESET}")
        
        # Execute nmap LOCALLY on bridge (avoid remote server timeout)
        cmd_parts = ["nmap"]
        if scan_type:
            cmd_parts.extend(scan_type.split())
        if ports:
            cmd_parts.extend(["-p", ports])
        if additional_args:
            cmd_parts.extend(additional_args.split())
        cmd_parts.append(target)
        
        cmd = " ".join(cmd_parts)
        logger.info(f"🔧 Running local nmap: {cmd}")
        
        try:
            proc = subprocess.run(cmd_parts, capture_output=True, text=True, timeout=300)
            elapsed = time.time() - start
            result = {
                "success": proc.returncode == 0,
                "return_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "tool": "nmap",
                "target": target,
                "execution_time": round(elapsed, 2),
                "timed_out": False
            }
            logger.info(f"✅ Nmap completed in {elapsed:.1f}s (rc={proc.returncode})")
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start
            result = {
                "success": False,
                "error": f"Nmap timed out after 300s",
                "tool": "nmap",
                "target": target,
                "execution_time": round(elapsed, 2),
                "timed_out": True
            }
            logger.error(f"❌ Nmap timed out after {elapsed:.1f}s")

        return result

    @mcp.tool()
    def nuclei_scan(target: str, severity: str = "", tags: str = "", template: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Execute Nuclei vulnerability scan with progress feedback."""
        data = {
            "target": target,
            "severity": severity,
            "tags": tags,
            "template": template,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"{HexStrikeColors.BLOOD_RED}🔬 Starting Nuclei vulnerability scan: {target}{HexStrikeColors.RESET}")
        result = hexstrike_client.submit_async_task("api/tools/nuclei", data, "nuclei", target)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Nuclei scan completed for {target}{HexStrikeColors.RESET}")
            if result.get("stdout") and "CRITICAL" in result["stdout"]:
                logger.warning(f"{HexStrikeColors.CRITICAL} CRITICAL vulnerabilities detected! {HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Nuclei scan failed for {target}{HexStrikeColors.RESET}")

        return result

    @mcp.tool()
    def gobuster_scan(url: str, mode: str = "dir", wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """Execute Gobuster scan with progress feedback."""
        data = {
            "url": url,
            "mode": mode,
            "wordlist": wordlist,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"{HexStrikeColors.CRIMSON}📁 Starting Gobuster {mode} scan: {url}{HexStrikeColors.RESET}")
        result = hexstrike_client.submit_async_task("api/tools/gobuster", data, "gobuster", url)

        if result.get("success"):
            logger.info(f"{HexStrikeColors.SUCCESS}✅ Gobuster scan completed for {url}{HexStrikeColors.RESET}")
        else:
            logger.error(f"{HexStrikeColors.ERROR}❌ Gobuster scan failed for {url}{HexStrikeColors.RESET}")
            if result.get("alternative_tool_suggested"):
                logger.info(f"{HexStrikeColors.HIGHLIGHT_BLUE} Alternative tool suggested: {result['alternative_tool_suggested']} {HexStrikeColors.RESET}")

        return result

    # ========================================================================
    # TASK MANAGEMENT TOOLS
    # ========================================================================

    @mcp.tool()
    def list_running_tasks() -> Dict[str, Any]:
        """List all currently running async tasks and their progress."""
        tasks = hexstrike_client.list_active_tasks()
        logger.info(f"📋 Active tasks: {json.dumps(tasks, indent=2)}")
        return tasks

    @mcp.tool()
    def resume_scan_task(task_id: str) -> Dict[str, Any]:
        """Resume a previously timed-out or interrupted scan task."""
        logger.info(f"🔄 Resuming task: {task_id}")
        result = hexstrike_client.resume_task(task_id)
        if result.get("success"):
            logger.info(f"✅ Task {task_id} resumed successfully")
        else:
            logger.error(f"❌ Failed to resume task {task_id}")
        return result

    @mcp.tool()
    def get_task_status(task_id: str) -> Dict[str, Any]:
        """Get the current status of a specific task."""
        task_info = task_tracker.get_task_info(task_id)
        if task_info:
            return {
                "task_id": task_id,
                "tracker_info": task_info,
                "success": True
            }
        return {"task_id": task_id, "found": False, "success": False}

    # ========================================================================
    # ADDITIONAL TOOLS (keep existing implementations, just wrap with async)
    # ========================================================================

    # For brevity, showing the pattern. All other tools follow the same structure:
    # 1. Log start
    # 2. Call submit_async_task() instead of safe_post()
    # 3. Log completion/failure

    @mcp.tool()
    def rustscan_fast_scan(target: str, ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Execute Rustscan for fast port scanning with progress feedback."""
        data = {"target": target, "ports": ports, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"⚡ Starting Rustscan: {target}")
        return hexstrike_client.submit_async_task("api/tools/rustscan", data, "rustscan", target)

    @mcp.tool()
    def masscan_high_speed(target: str, ports: str = "1-65535", rate: str = "10000", additional_args: str = "") -> Dict[str, Any]:
        """Execute Masscan for high-speed port scanning with progress feedback."""
        data = {"target": target, "ports": ports, "rate": rate, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🌊 Starting Masscan: {target} (rate: {rate}/s)")
        return hexstrike_client.submit_async_task("api/tools/masscan", data, "masscan", target)

    @mcp.tool()
    def sqlmap_scan(target: str, level: int = 1, risk: int = 1, additional_args: str = "") -> Dict[str, Any]:
        """Execute SQLmap for SQL injection testing with progress feedback."""
        data = {"target": target, "level": level, "risk": risk, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"💉 Starting SQLmap: {target}")
        return hexstrike_client.submit_async_task("api/tools/sqlmap", data, "sqlmap", target)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", mode: str = "dir", additional_args: str = "") -> Dict[str, Any]:
        """Execute FFUF for fuzzing with progress feedback."""
        data = {"url": url, "wordlist": wordlist, "mode": mode, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🔥 Starting FFUF fuzzing: {url}")
        return hexstrike_client.submit_async_task("api/tools/ffuf", data, "ffuf", url)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Execute Nikto web server scan with progress feedback."""
        data = {"target": target, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🕷️  Starting Nikto scan: {target}")
        return hexstrike_client.submit_async_task("api/tools/nikto", data, "nikto", target)

    @mcp.tool()
    def dirsearch_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", extensions: str = "php,asp,aspx,jsp", additional_args: str = "") -> Dict[str, Any]:
        """Execute Dirsearch directory scan with progress feedback."""
        data = {"url": url, "wordlist": wordlist, "extensions": extensions, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"📂 Starting Dirsearch: {url}")
        return hexstrike_client.submit_async_task("api/tools/dirsearch", data, "dirsearch", url)

    @mcp.tool()
    def wpscan_analyze(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Execute WPScan WordPress analysis with progress feedback."""
        data = {"target": target, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🔍 Starting WPScan: {target}")
        return hexstrike_client.submit_async_task("api/tools/wpscan", data, "wpscan", target)

    @mcp.tool()
    def hydra_attack(target: str, service: str = "ssh", username: str = "", password_file: str = "", additional_args: str = "") -> Dict[str, Any]:
        """Execute Hydra brute force attack with progress feedback."""
        data = {"target": target, "service": service, "username": username, "password_file": password_file, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🔓 Starting Hydra attack: {target}/{service}")
        return hexstrike_client.submit_async_task("api/tools/hydra", data, "hydra", target)

    @mcp.tool()
    def katana_crawl(url: str, depth: int = 3, additional_args: str = "") -> Dict[str, Any]:
        """Execute Katana web crawler with progress feedback."""
        data = {"url": url, "depth": depth, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🕸️  Starting Katana crawl: {url}")
        return hexstrike_client.submit_async_task("api/tools/katana", data, "katana", url)

    @mcp.tool()
    def amass_scan(domain: str, mode: str = "enum", additional_args: str = "") -> Dict[str, Any]:
        """Execute Amass subdomain enumeration with progress feedback."""
        data = {"domain": domain, "mode": mode, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🔎 Starting Amass enumeration: {domain}")
        return hexstrike_client.submit_async_task("api/tools/amass", data, "amass", domain)

    @mcp.tool()
    def subfinder_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """Execute Subfinder subdomain discovery with progress feedback."""
        data = {"domain": domain, "additional_args": additional_args, "use_recovery": True}
        logger.info(f"🔎 Starting Subfinder: {domain}")
        return hexstrike_client.submit_async_task("api/tools/subfinder", data, "subfinder", domain)

    # ========================================================================
    # P0 NEW TOOLS: Metasploit, Pwntools, JWT Analyzer, GraphQL
    # ========================================================================

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = None, async_mode: bool = True) -> Dict[str, Any]:
        """
        Execute a Metasploit Framework module via msfconsole resource script.

        Args:
            module: MSF module path (e.g. "exploit/windows/smb/ms17_010_eternalblue")
            options: Module options as dict (e.g. {"RHOSTS": "10.10.10.1", "LPORT": 4444})
            async_mode: Run asynchronously (default True for long exploits)
        """
        if options is None:
            options = {}
        data = {"module": module, "options": options, "async": async_mode}
        target = options.get("RHOSTS", options.get("LHOST", module))
        logger.info(f"🚀 Metasploit: {module} -> {target}")
        result = hexstrike_client.submit_async_task("api/tools/metasploit", data, "metasploit", target)
        if result.get("success"):
            logger.info(f"✅ Metasploit completed: {module}")
        else:
            logger.error(f"❌ Metasploit failed: {module}")
        return result

    @mcp.tool()
    def msfvenom_generate(payload: str, format_type: str = "", output_file: str = "",
                          encoder: str = "", iterations: int = 0,
                          additional_args: str = "", async_mode: bool = False) -> Dict[str, Any]:
        """
        Generate payloads with MSFVenom.

        Args:
            payload: Payload name (e.g. "windows/x64/meterpreter/reverse_tcp")
            format_type: Output format (exe, elf, raw, python, etc.)
            output_file: Save payload to file
            encoder: Encoder to use (e.g. "x86/shikata_ga_nai")
            iterations: Number of encoding iterations
            additional_args: Extra msfvenom arguments
            async_mode: Run asynchronously
        """
        data = {"payload": payload, "async": async_mode}
        if format_type:
            data["format"] = format_type
        if output_file:
            data["output_file"] = output_file
        if encoder:
            data["encoder"] = encoder
        if iterations:
            data["iterations"] = iterations
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"🔧 MSFVenom generating: {payload}")
        if async_mode:
            return hexstrike_client.submit_async_task("api/tools/msfvenom", data, "msfvenom", payload)
        return hexstrike_client.safe_post("api/tools/msfvenom", data)

    @mcp.tool()
    def pwntools_exploit(script_content: str = "", target_binary: str = "",
                         target_host: str = "", target_port: int = 0,
                         exploit_type: str = "local",
                         additional_args: str = "", async_mode: bool = True) -> Dict[str, Any]:
        """
        Execute pwntools exploit script (requires /tools/tools-venv).

        Args:
            script_content: Full Python exploit script using pwntools
            target_binary: Local binary path to exploit
            target_host: Remote target host
            target_port: Remote target port
            exploit_type: local | remote | format_string | rop
            additional_args: Extra arguments
            async_mode: Run asynchronously (default True)
        """
        data = {"exploit_type": exploit_type, "async": async_mode}
        if script_content:
            data["script_content"] = script_content
        if target_binary:
            data["target_binary"] = target_binary
        if target_host:
            data["target_host"] = target_host
        if target_port:
            data["target_port"] = target_port
        if additional_args:
            data["additional_args"] = additional_args
        target = target_binary or target_host or "pwntools_exploit"
        logger.info(f"🔧 Pwntools exploit ({exploit_type}): {target}")
        result = hexstrike_client.submit_async_task("api/tools/pwntools", data, "pwntools", target)
        if result.get("success"):
            logger.info(f"✅ Pwntools exploit completed")
        else:
            logger.error(f"❌ Pwntools exploit failed")
        return result

    @mcp.tool()
    def jwt_analyze(jwt_token: str, target_url: str = "", async_mode: bool = False) -> Dict[str, Any]:
        """
        Analyze JWT token for vulnerabilities (none algorithm, key confusion, etc.)

        Args:
            jwt_token: The JWT token to analyze
            target_url: Optional target URL to test token manipulation attacks
            async_mode: Run asynchronously
        """
        data = {"jwt_token": jwt_token, "async": async_mode}
        if target_url:
            data["target_url"] = target_url
        logger.info(f"🔐 JWT Analysis: {jwt_token[:30]}...")
        if async_mode:
            return hexstrike_client.submit_async_task("api/tools/jwt_analyzer", data, "jwt_analyzer", jwt_token[:30])
        return hexstrike_client.safe_post("api/tools/jwt_analyzer", data)

    @mcp.tool()
    def graphql_scan(endpoint: str, scan_type: str = "full",
                     additional_args: str = "", async_mode: bool = True) -> Dict[str, Any]:
        """
        Scan GraphQL endpoint for security vulnerabilities using graphql-scanner tool.

        Args:
            endpoint: GraphQL endpoint URL
            scan_type: full | introspection | depth | batch (default: full)
            additional_args: Extra command-line arguments
            async_mode: Run asynchronously
        """
        data = {"endpoint": endpoint, "scan_type": scan_type, "async": async_mode}
        if additional_args:
            data["additional_args"] = additional_args
        logger.info(f"🌐 GraphQL scan: {endpoint} (type: {scan_type})")
        result = hexstrike_client.submit_async_task("api/tools/graphql_scanner", data, "graphql_scanner", endpoint)
        if result.get("success"):
            logger.info(f"✅ GraphQL scan completed")
        else:
            logger.error(f"❌ GraphQL scan failed")
        return result

    @mcp.tool()
    def shodan_query(query: str = "", host: str = "", async_mode: bool = True) -> Dict[str, Any]:
        """
        Search Shodan for internet-connected devices.

        Args:
            query: Shodan search query (e.g. "apache country:CN")
            host: Specific IP/host to look up (e.g. "1.2.3.4")
            async_mode: Run asynchronously
        """
        data = {"async": async_mode}
        if query:
            data["query"] = query
        if host:
            data["host"] = host
        target = host or query or "shodan"
        logger.info(f"🔍 Shodan: {target}")
        result = hexstrike_client.submit_async_task("api/tools/shodan_search", data, "shodan_search", target)
        if result.get("success"):
            logger.info(f"✅ Shodan search completed")
        else:
            logger.error(f"❌ Shodan search failed")
        return result

    @mcp.tool()
    def censys_query(query: str = "", host: str = "", async_mode: bool = True) -> Dict[str, Any]:
        """
        Search Censys for internet-connected assets.

        Args:
            query: Censys search query (e.g. "services.http.response.headers:nginx")
            host: Specific IP/host to look up (e.g. "1.2.3.4")
            async_mode: Run asynchronously
        """
        data = {"async": async_mode}
        if query:
            data["query"] = query
        if host:
            data["host"] = host
        target = host or query or "censys"
        logger.info(f"🔍 Censys: {target}")
        result = hexstrike_client.submit_async_task("api/tools/censys_search", data, "censys_search", target)
        if result.get("success"):
            logger.info(f"✅ Censys search completed")
        else:
            logger.error(f"❌ Censys search failed")
        return result

    # ========================================================================
    # TASK DASHBOARD
    # ===========================================================================

    @mcp.tool()
    def scan_dashboard() -> Dict[str, Any]:
        """Get a comprehensive dashboard of all scan activities."""
        active = hexstrike_client.list_active_tasks()
        tracker_tasks = task_tracker.active_tasks

        dashboard = {
            "timestamp": datetime.now().isoformat(),
            "server_tasks": active,
            "local_tracker": {k: {kk: vv for kk, vv in v.items() if kk != "_lock"} for k, v in tracker_tasks.items()},
            "summary": {
                "total_tracked": len(tracker_tasks),
                "active": sum(1 for v in tracker_tasks.values() if v.get("status") == "running"),
                "completed": sum(1 for v in tracker_tasks.values() if v.get("status") == "completed"),
                "failed": sum(1 for v in tracker_tasks.values() if v.get("status") == "failed"),
            }
        }
        logger.info(f"📊 Scan Dashboard: {json.dumps(dashboard['summary'], indent=2)}")
        return dashboard

    # ========================================================================
    # AUTO-ADDED: Web Recon & Scanning (20 tools)
    # ========================================================================

    @mcp.tool()
    def httpx(url: str, additional_args: str = "") -> Dict[str, Any]:
        """HTTP service fingerprinting and tech detection."""
        data = {
            "url": url,
            "target": url,
            "additional_args": additional_args,
            "use_recovery": False
        }
        logger.info(f"Starting httpx: {url}")
        result = hexstrike_client.submit_async_task("api/tools/httpx", data, "httpx", url)
        if result.get("success"):
            logger.info(f"httpx completed for {url}")
        else:
            logger.error(f"httpx failed for {url}")
        return result

    @mcp.tool()
    def wafw00f(url: str, additional_args: str = "") -> Dict[str, Any]:
        """WAF detection and identification."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting wafw00f: {url}")
        result = hexstrike_client.submit_async_task("api/tools/wafw00f", data, "wafw00f", url)
        if result.get("success"):
            logger.info(f"wafw00f completed for {url}")
        else:
            logger.error(f"wafw00f failed for {url}")
        return result

    @mcp.tool()
    def dirb(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Directory brute force scanning."""
        data = {
            "url": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting dirb: {url}")
        result = hexstrike_client.submit_async_task("api/tools/dirb", data, "dirb", url)
        if result.get("success"):
            logger.info(f"dirb completed for {url}")
        else:
            logger.error(f"dirb failed for {url}")
        return result

    @mcp.tool()
    def feroxbuster(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Fast recursive content discovery."""
        data = {
            "url": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting feroxbuster: {url}")
        result = hexstrike_client.submit_async_task("api/tools/feroxbuster", data, "feroxbuster", url)
        if result.get("success"):
            logger.info(f"feroxbuster completed for {url}")
        else:
            logger.error(f"feroxbuster failed for {url}")
        return result

    @mcp.tool()
    def arjun(url: str, additional_args: str = "") -> Dict[str, Any]:
        """HTTP parameter discovery."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting arjun: {url}")
        result = hexstrike_client.submit_async_task("api/tools/arjun", data, "arjun", url)
        if result.get("success"):
            logger.info(f"arjun completed for {url}")
        else:
            logger.error(f"arjun failed for {url}")
        return result

    @mcp.tool()
    def dalfox(url: str, additional_args: str = "") -> Dict[str, Any]:
        """XSS parameter analysis and detection."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting dalfox: {url}")
        result = hexstrike_client.submit_async_task("api/tools/dalfox", data, "dalfox", url)
        if result.get("success"):
            logger.info(f"dalfox completed for {url}")
        else:
            logger.error(f"dalfox failed for {url}")
        return result

    @mcp.tool()
    def hakrawler(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Web spider for endpoint discovery."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting hakrawler: {url}")
        result = hexstrike_client.submit_async_task("api/tools/hakrawler", data, "hakrawler", url)
        if result.get("success"):
            logger.info(f"hakrawler completed for {url}")
        else:
            logger.error(f"hakrawler failed for {url}")
        return result

    @mcp.tool()
    def paramspider(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Web parameter mining and discovery."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting paramspider: {url}")
        result = hexstrike_client.submit_async_task("api/tools/paramspider", data, "paramspider", url)
        if result.get("success"):
            logger.info(f"paramspider completed for {url}")
        else:
            logger.error(f"paramspider failed for {url}")
        return result

    @mcp.tool()
    def qsreplace(url: str, additional_args: str = "") -> Dict[str, Any]:
        """URL query string parameter replacement for testing."""
        data = {
            "url": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting qsreplace: {url}")
        result = hexstrike_client.submit_async_task("api/tools/qsreplace", data, "qsreplace", url)
        if result.get("success"):
            logger.info(f"qsreplace completed for {url}")
        else:
            logger.error(f"qsreplace failed for {url}")
        return result

    @mcp.tool()
    def waybackurls(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """Fetch historical URLs from Wayback Machine."""
        data = {
            "domain": domain,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting waybackurls: {domain}")
        result = hexstrike_client.submit_async_task("api/tools/waybackurls", data, "waybackurls", domain)
        if result.get("success"):
            logger.info(f"waybackurls completed for {domain}")
        else:
            logger.error(f"waybackurls failed for {domain}")
        return result

    @mcp.tool()
    def wfuzz(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Web application fuzzing framework."""
        data = {
            "url": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting wfuzz: {url}")
        result = hexstrike_client.submit_async_task("api/tools/wfuzz", data, "wfuzz", url)
        if result.get("success"):
            logger.info(f"wfuzz completed for {url}")
        else:
            logger.error(f"wfuzz failed for {url}")
        return result

    @mcp.tool()
    def xsser(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Automated XSS detection and exploitation."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting xsser: {url}")
        result = hexstrike_client.submit_async_task("api/tools/xsser", data, "xsser", url)
        if result.get("success"):
            logger.info(f"xsser completed for {url}")
        else:
            logger.error(f"xsser failed for {url}")
        return result

    @mcp.tool()
    def anew(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Append new lines from stdin to file."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting anew: {target}")
        result = hexstrike_client.submit_async_task("api/tools/anew", data, "anew", target)
        if result.get("success"):
            logger.info(f"anew completed for {target}")
        else:
            logger.error(f"anew failed for {target}")
        return result

    @mcp.tool()
    def uro(url: str, additional_args: str = "") -> Dict[str, Any]:
        """Remove duplicate URLs from list."""
        data = {
            "url": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting uro: {url}")
        result = hexstrike_client.submit_async_task("api/tools/uro", data, "uro", url)
        if result.get("success"):
            logger.info(f"uro completed for {url}")
        else:
            logger.error(f"uro failed for {url}")
        return result

    @mcp.tool()
    def dotdotpwn(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Directory traversal fuzzing."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting dotdotpwn: {target}")
        result = hexstrike_client.submit_async_task("api/tools/dotdotpwn", data, "dotdotpwn", target)
        if result.get("success"):
            logger.info(f"dotdotpwn completed for {target}")
        else:
            logger.error(f"dotdotpwn failed for {target}")
        return result

    @mcp.tool()
    def fierce(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """DNS reconnaissance and subdomain enumeration."""
        data = {
            "domain": domain,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting fierce: {domain}")
        result = hexstrike_client.submit_async_task("api/tools/fierce", data, "fierce", domain)
        if result.get("success"):
            logger.info(f"fierce completed for {domain}")
        else:
            logger.error(f"fierce failed for {domain}")
        return result

    @mcp.tool()
    def dnsenum(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """DNS enumeration and zone transfer."""
        data = {
            "domain": domain,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting dnsenum: {domain}")
        result = hexstrike_client.submit_async_task("api/tools/dnsenum", data, "dnsenum", domain)
        if result.get("success"):
            logger.info(f"dnsenum completed for {domain}")
        else:
            logger.error(f"dnsenum failed for {domain}")
        return result

    @mcp.tool()
    def curl(url: str, additional_args: str = "") -> Dict[str, Any]:
        """HTTP client for endpoint testing."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting curl: {url}")
        result = hexstrike_client.submit_async_task("api/tools/curl", data, "curl", url)
        if result.get("success"):
            logger.info(f"curl completed for {url}")
        else:
            logger.error(f"curl failed for {url}")
        return result

    @mcp.tool()
    def httpie(url: str, additional_args: str = "") -> Dict[str, Any]:
        """User-friendly HTTP client for API testing."""
        data = {
            "target": url,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting httpie: {url}")
        result = hexstrike_client.submit_async_task("api/tools/httpie", data, "httpie", url)
        if result.get("success"):
            logger.info(f"httpie completed for {url}")
        else:
            logger.error(f"httpie failed for {url}")
        return result

    @mcp.tool()
    def autorecon(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Multi-threaded service-aware reconnaissance."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting autorecon: {target}")
        result = hexstrike_client.submit_async_task("api/tools/autorecon", data, "autorecon", target)
        if result.get("success"):
            logger.info(f"autorecon completed for {target}")
        else:
            logger.error(f"autorecon failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Network & Active Directory (10 tools)
    # ========================================================================

    @mcp.tool()
    def arp_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """ARP network scanner for local discovery."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting arp-scan: {target}")
        result = hexstrike_client.submit_async_task("api/tools/arp_scan", data, "arp_scan", target)
        if result.get("success"):
            logger.info(f"arp-scan completed for {target}")
        else:
            logger.error(f"arp-scan failed for {target}")
        return result

    @mcp.tool()
    def enum4linux(target: str, additional_args: str = "") -> Dict[str, Any]:
        """SMB enumeration and information gathering."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting enum4linux: {target}")
        result = hexstrike_client.submit_async_task("api/tools/enum4linux", data, "enum4linux", target)
        if result.get("success"):
            logger.info(f"enum4linux completed for {target}")
        else:
            logger.error(f"enum4linux failed for {target}")
        return result

    @mcp.tool()
    def enum4linux_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """SMB enumeration (next-gen)."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting enum4linux-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/enum4linux_ng", data, "enum4linux_ng", target)
        if result.get("success"):
            logger.info(f"enum4linux-ng completed for {target}")
        else:
            logger.error(f"enum4linux-ng failed for {target}")
        return result

    @mcp.tool()
    def nbtscan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """NetBIOS name scanner."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting nbtscan: {target}")
        result = hexstrike_client.submit_async_task("api/tools/nbtscan", data, "nbtscan", target)
        if result.get("success"):
            logger.info(f"nbtscan completed for {target}")
        else:
            logger.error(f"nbtscan failed for {target}")
        return result

    @mcp.tool()
    def smbmap(target: str, additional_args: str = "") -> Dict[str, Any]:
        """SMB share enumeration and access mapping."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting smbmap: {target}")
        result = hexstrike_client.submit_async_task("api/tools/smbmap", data, "smbmap", target)
        if result.get("success"):
            logger.info(f"smbmap completed for {target}")
        else:
            logger.error(f"smbmap failed for {target}")
        return result

    @mcp.tool()
    def evil_winrm(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Windows RM shell for penetration testing."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting evil-winrm: {target}")
        result = hexstrike_client.submit_async_task("api/tools/evil_winrm", data, "evil_winrm", target)
        if result.get("success"):
            logger.info(f"evil-winrm completed for {target}")
        else:
            logger.error(f"evil-winrm failed for {target}")
        return result

    @mcp.tool()
    def rpcclient(target: str, additional_args: str = "") -> Dict[str, Any]:
        """RPC client for Windows enumeration."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting rpcclient: {target}")
        result = hexstrike_client.submit_async_task("api/tools/rpcclient", data, "rpcclient", target)
        if result.get("success"):
            logger.info(f"rpcclient completed for {target}")
        else:
            logger.error(f"rpcclient failed for {target}")
        return result

    @mcp.tool()
    def responder(target: str, additional_args: str = "") -> Dict[str, Any]:
        """LLMNR/NBT-NS/mDNS poisoner and responder."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting responder: {target}")
        result = hexstrike_client.submit_async_task("api/tools/responder", data, "responder", target)
        if result.get("success"):
            logger.info(f"responder completed for {target}")
        else:
            logger.error(f"responder failed for {target}")
        return result

    @mcp.tool()
    def tcpdump(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Network packet capture and analysis."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting tcpdump: {target}")
        result = hexstrike_client.submit_async_task("api/tools/tcpdump", data, "tcpdump", target)
        if result.get("success"):
            logger.info(f"tcpdump completed for {target}")
        else:
            logger.error(f"tcpdump failed for {target}")
        return result

    @mcp.tool()
    def kismet(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Wireless network detector and sniffer."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting kismet: {target}")
        result = hexstrike_client.submit_async_task("api/tools/kismet", data, "kismet", target)
        if result.get("success"):
            logger.info(f"kismet completed for {target}")
        else:
            logger.error(f"kismet failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Password Cracking (5 tools)
    # ========================================================================

    @mcp.tool()
    def hashcat(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Advanced GPU-accelerated password recovery."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting hashcat: {target}")
        result = hexstrike_client.submit_async_task("api/tools/hashcat", data, "hashcat", target)
        if result.get("success"):
            logger.info(f"hashcat completed for {target}")
        else:
            logger.error(f"hashcat failed for {target}")
        return result

    @mcp.tool()
    def john(target: str, additional_args: str = "") -> Dict[str, Any]:
        """John the Ripper password cracker."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting john: {target}")
        result = hexstrike_client.submit_async_task("api/tools/john", data, "john", target)
        if result.get("success"):
            logger.info(f"john completed for {target}")
        else:
            logger.error(f"john failed for {target}")
        return result

    @mcp.tool()
    def medusa(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Fast parallel login brute forcer."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting medusa: {target}")
        result = hexstrike_client.submit_async_task("api/tools/medusa", data, "medusa", target)
        if result.get("success"):
            logger.info(f"medusa completed for {target}")
        else:
            logger.error(f"medusa failed for {target}")
        return result

    @mcp.tool()
    def ophcrack(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Windows password cracker using rainbow tables."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting ophcrack: {target}")
        result = hexstrike_client.submit_async_task("api/tools/ophcrack", data, "ophcrack", target)
        if result.get("success"):
            logger.info(f"ophcrack completed for {target}")
        else:
            logger.error(f"ophcrack failed for {target}")
        return result

    @mcp.tool()
    def hash_identifier(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Automatic hash type identification."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting hash-identifier: {target}")
        result = hexstrike_client.submit_async_task("api/tools/hash_identifier", data, "hash_identifier", target)
        if result.get("success"):
            logger.info(f"hash-identifier completed for {target}")
        else:
            logger.error(f"hash-identifier failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Wireless Security (4 tools)
    # ========================================================================

    @mcp.tool()
    def aircrack_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """WEP/WPA/WPA2 cracking suite."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting aircrack-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/aircrack_ng", data, "aircrack_ng", target)
        if result.get("success"):
            logger.info(f"aircrack-ng completed for {target}")
        else:
            logger.error(f"aircrack-ng failed for {target}")
        return result

    @mcp.tool()
    def aireplay_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Wireless packet injection tool."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting aireplay-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/aireplay_ng", data, "aireplay_ng", target)
        if result.get("success"):
            logger.info(f"aireplay-ng completed for {target}")
        else:
            logger.error(f"aireplay-ng failed for {target}")
        return result

    @mcp.tool()
    def airmon_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Wireless monitor mode setup."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting airmon-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/airmon_ng", data, "airmon_ng", target)
        if result.get("success"):
            logger.info(f"airmon-ng completed for {target}")
        else:
            logger.error(f"airmon-ng failed for {target}")
        return result

    @mcp.tool()
    def airodump_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Wireless packet capture and monitoring."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting airodump-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/airodump_ng", data, "airodump_ng", target)
        if result.get("success"):
            logger.info(f"airodump-ng completed for {target}")
        else:
            logger.error(f"airodump-ng failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Forensics & File Analysis (11 tools)
    # ========================================================================

    @mcp.tool()
    def binwalk(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Firmware analysis and extraction."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting binwalk: {target}")
        result = hexstrike_client.submit_async_task("api/tools/binwalk", data, "binwalk", target)
        if result.get("success"):
            logger.info(f"binwalk completed for {target}")
        else:
            logger.error(f"binwalk failed for {target}")
        return result

    @mcp.tool()
    def exiftool(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Metadata extraction and manipulation."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting exiftool: {target}")
        result = hexstrike_client.submit_async_task("api/tools/exiftool", data, "exiftool", target)
        if result.get("success"):
            logger.info(f"exiftool completed for {target}")
        else:
            logger.error(f"exiftool failed for {target}")
        return result

    @mcp.tool()
    def foremost(target: str, additional_args: str = "") -> Dict[str, Any]:
        """File carving from disk images."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting foremost: {target}")
        result = hexstrike_client.submit_async_task("api/tools/foremost", data, "foremost", target)
        if result.get("success"):
            logger.info(f"foremost completed for {target}")
        else:
            logger.error(f"foremost failed for {target}")
        return result

    @mcp.tool()
    def scalpel(target: str, additional_args: str = "") -> Dict[str, Any]:
        """File carving with signature matching."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting scalpel: {target}")
        result = hexstrike_client.submit_async_task("api/tools/scalpel", data, "scalpel", target)
        if result.get("success"):
            logger.info(f"scalpel completed for {target}")
        else:
            logger.error(f"scalpel failed for {target}")
        return result

    @mcp.tool()
    def photorec(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Photo and file recovery from disk."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting photorec: {target}")
        result = hexstrike_client.submit_async_task("api/tools/photorec", data, "photorec", target)
        if result.get("success"):
            logger.info(f"photorec completed for {target}")
        else:
            logger.error(f"photorec failed for {target}")
        return result

    @mcp.tool()
    def testdisk(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Disk partition recovery and repair."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting testdisk: {target}")
        result = hexstrike_client.submit_async_task("api/tools/testdisk", data, "testdisk", target)
        if result.get("success"):
            logger.info(f"testdisk completed for {target}")
        else:
            logger.error(f"testdisk failed for {target}")
        return result

    @mcp.tool()
    def steghide(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Steganography embedding and extraction."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting steghide: {target}")
        result = hexstrike_client.submit_async_task("api/tools/steghide", data, "steghide", target)
        if result.get("success"):
            logger.info(f"steghide completed for {target}")
        else:
            logger.error(f"steghide failed for {target}")
        return result

    @mcp.tool()
    def zsteg(target: str, additional_args: str = "") -> Dict[str, Any]:
        """PNG/BMP steganography detector."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting zsteg: {target}")
        result = hexstrike_client.submit_async_task("api/tools/zsteg", data, "zsteg", target)
        if result.get("success"):
            logger.info(f"zsteg completed for {target}")
        else:
            logger.error(f"zsteg failed for {target}")
        return result

    @mcp.tool()
    def file(target: str, additional_args: str = "") -> Dict[str, Any]:
        """File type identification."""
        import subprocess
        try:
            command = f"file {target}"
            if additional_args:
                command += f" {additional_args}"
            logger.info(f"Starting file (local): {target}")
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
            return {
                "success": True,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode,
                "tool": "file",
                "target": target
            }
        except Exception as e:
            logger.error(f"file failed for {target}: {str(e)}")
            return {"success": False, "error": str(e), "tool": "file", "target": target}

    @mcp.tool()
    def strings(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Extract printable strings from binary files."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting strings: {target}")
        result = hexstrike_client.submit_async_task("api/tools/strings", data, "strings", target)
        if result.get("success"):
            logger.info(f"strings completed for {target}")
        else:
            logger.error(f"strings failed for {target}")
        return result

    @mcp.tool()
    def xxd(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Hex dump utility for binary inspection."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting xxd: {target}")
        result = hexstrike_client.submit_async_task("api/tools/xxd", data, "xxd", target)
        if result.get("success"):
            logger.info(f"xxd completed for {target}")
        else:
            logger.error(f"xxd failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Reverse Engineering & Debugging (5 tools)
    # ========================================================================

    @mcp.tool()
    def angr(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Binary analysis framework for exploitation."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting angr: {target}")
        result = hexstrike_client.submit_async_task("api/tools/angr", data, "angr", target)
        if result.get("success"):
            logger.info(f"angr completed for {target}")
        else:
            logger.error(f"angr failed for {target}")
        return result

    @mcp.tool()
    def gdb(target: str, additional_args: str = "") -> Dict[str, Any]:
        """GNU debugger for runtime analysis."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting gdb: {target}")
        result = hexstrike_client.submit_async_task("api/tools/gdb", data, "gdb", target)
        if result.get("success"):
            logger.info(f"gdb completed for {target}")
        else:
            logger.error(f"gdb failed for {target}")
        return result

    @mcp.tool()
    def ghidra(target: str, additional_args: str = "") -> Dict[str, Any]:
        """NSA software reverse engineering suite."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting ghidra: {target}")
        result = hexstrike_client.submit_async_task("api/tools/ghidra", data, "ghidra", target)
        if result.get("success"):
            logger.info(f"ghidra completed for {target}")
        else:
            logger.error(f"ghidra failed for {target}")
        return result

    @mcp.tool()
    def radare2(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Reverse engineering framework."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting radare2: {target}")
        result = hexstrike_client.submit_async_task("api/tools/radare2", data, "radare2", target)
        if result.get("success"):
            logger.info(f"radare2 completed for {target}")
        else:
            logger.error(f"radare2 failed for {target}")
        return result

    @mcp.tool()
    def objdump(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Binary object file disassembly."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting objdump: {target}")
        result = hexstrike_client.submit_async_task("api/tools/objdump", data, "objdump", target)
        if result.get("success"):
            logger.info(f"objdump completed for {target}")
        else:
            logger.error(f"objdump failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: OSINT & Social Recon (5 tools)
    # ========================================================================

    @mcp.tool()
    def sherlock(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Social media username search across platforms."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting sherlock: {target}")
        result = hexstrike_client.submit_async_task("api/tools/sherlock", data, "sherlock", target)
        if result.get("success"):
            logger.info(f"sherlock completed for {target}")
        else:
            logger.error(f"sherlock failed for {target}")
        return result

    @mcp.tool()
    def spiderfoot(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Automated OSINT data gathering."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting spiderfoot: {target}")
        result = hexstrike_client.submit_async_task("api/tools/spiderfoot", data, "spiderfoot", target)
        if result.get("success"):
            logger.info(f"spiderfoot completed for {target}")
        else:
            logger.error(f"spiderfoot failed for {target}")
        return result

    @mcp.tool()
    def theharvester(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Email and subdomain harvesting from public sources."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting theharvester: {target}")
        result = hexstrike_client.submit_async_task("api/tools/theharvester", data, "theharvester", target)
        if result.get("success"):
            logger.info(f"theharvester completed for {target}")
        else:
            logger.error(f"theharvester failed for {target}")
        return result

    @mcp.tool()
    def maltego(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Link analysis and data mining platform."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting maltego: {target}")
        result = hexstrike_client.submit_async_task("api/tools/maltego", data, "maltego", target)
        if result.get("success"):
            logger.info(f"maltego completed for {target}")
        else:
            logger.error(f"maltego failed for {target}")
        return result

    @mcp.tool()
    def recon_ng(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Modular reconnaissance framework."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting recon-ng: {target}")
        result = hexstrike_client.submit_async_task("api/tools/recon_ng", data, "recon_ng", target)
        if result.get("success"):
            logger.info(f"recon-ng completed for {target}")
        else:
            logger.error(f"recon-ng failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Exploit & Payload (4 tools)
    # ========================================================================

    @mcp.tool()
    def searchsploit(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Exploit-DB offline search engine."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting searchsploit: {target}")
        result = hexstrike_client.submit_async_task("api/tools/searchsploit", data, "searchsploit", target)
        if result.get("success"):
            logger.info(f"searchsploit completed for {target}")
        else:
            logger.error(f"searchsploit failed for {target}")
        return result

    @mcp.tool()
    def msfconsole(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Metasploit Framework console interface."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting msfconsole: {target}")
        result = hexstrike_client.submit_async_task("api/tools/msfconsole", data, "msfconsole", target)
        if result.get("success"):
            logger.info(f"msfconsole completed for {target}")
        else:
            logger.error(f"msfconsole failed for {target}")
        return result

    @mcp.tool()
    def patator(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Multi-purpose brute forcing tool."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting patator: {target}")
        result = hexstrike_client.submit_async_task("api/tools/patator", data, "patator", target)
        if result.get("success"):
            logger.info(f"patator completed for {target}")
        else:
            logger.error(f"patator failed for {target}")
        return result

    @mcp.tool()
    def nxc(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Network exploitation tool (crackmapexec fork)."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting nxc: {target}")
        result = hexstrike_client.submit_async_task("api/tools/nxc", data, "nxc", target)
        if result.get("success"):
            logger.info(f"nxc completed for {target}")
        else:
            logger.error(f"nxc failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Cloud Security (6 tools)
    # ========================================================================

    @mcp.tool()
    def checkov(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Infrastructure as code security scanning."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting checkov: {target}")
        result = hexstrike_client.submit_async_task("api/tools/checkov", data, "checkov", target)
        if result.get("success"):
            logger.info(f"checkov completed for {target}")
        else:
            logger.error(f"checkov failed for {target}")
        return result

    @mcp.tool()
    def trivy(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Container and filesystem vulnerability scanner."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting trivy: {target}")
        result = hexstrike_client.submit_async_task("api/tools/trivy", data, "trivy", target)
        if result.get("success"):
            logger.info(f"trivy completed for {target}")
        else:
            logger.error(f"trivy failed for {target}")
        return result

    @mcp.tool()
    def prowler(target: str, additional_args: str = "") -> Dict[str, Any]:
        """AWS security auditing and hardening."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting prowler: {target}")
        result = hexstrike_client.submit_async_task("api/tools/prowler", data, "prowler", target)
        if result.get("success"):
            logger.info(f"prowler completed for {target}")
        else:
            logger.error(f"prowler failed for {target}")
        return result

    @mcp.tool()
    def kube_hunter(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Kubernetes cluster penetration testing."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting kube-hunter: {target}")
        result = hexstrike_client.submit_async_task("api/tools/kube_hunter", data, "kube_hunter", target)
        if result.get("success"):
            logger.info(f"kube-hunter completed for {target}")
        else:
            logger.error(f"kube-hunter failed for {target}")
        return result

    @mcp.tool()
    def terrascan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """IaC security policy compliance checker."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting terrascan: {target}")
        result = hexstrike_client.submit_async_task("api/tools/terrascan", data, "terrascan", target)
        if result.get("success"):
            logger.info(f"terrascan completed for {target}")
        else:
            logger.error(f"terrascan failed for {target}")
        return result

    @mcp.tool()
    def checksec(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Binary security property analysis."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting checksec: {target}")
        result = hexstrike_client.submit_async_task("api/tools/checksec", data, "checksec", target)
        if result.get("success"):
            logger.info(f"checksec completed for {target}")
        else:
            logger.error(f"checksec failed for {target}")
        return result
    # ========================================================================
    # AUTO-ADDED: Misc (3 tools)
    # ========================================================================

    @mcp.tool()
    def burpsuite(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Burp Suite web security testing platform."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting burpsuite: {target}")
        result = hexstrike_client.submit_async_task("api/tools/burpsuite", data, "burpsuite", target)
        if result.get("success"):
            logger.info(f"burpsuite completed for {target}")
        else:
            logger.error(f"burpsuite failed for {target}")
        return result

    @mcp.tool()
    def autopsy(target: str, additional_args: str = "") -> Dict[str, Any]:
        """Digital forensics and incident response."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting autopsy: {target}")
        result = hexstrike_client.submit_async_task("api/tools/autopsy", data, "autopsy", target)
        if result.get("success"):
            logger.info(f"autopsy completed for {target}")
        else:
            logger.error(f"autopsy failed for {target}")
        return result

    @mcp.tool()
    def zaproxy(target: str, additional_args: str = "") -> Dict[str, Any]:
        """OWASP ZAP web application security scanner."""
        data = {
            "target": target,
            "additional_args": additional_args,
            "use_recovery": True
        }
        logger.info(f"Starting zaproxy: {target}")
        result = hexstrike_client.submit_async_task("api/tools/zaproxy", data, "zaproxy", target)
        if result.get("success"):
            logger.info(f"zaproxy completed for {target}")
        else:
            logger.error(f"zaproxy failed for {target}")
        return result

    return mcp

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def parse_args():
    parser = argparse.ArgumentParser(description="Run the HexStrike AI MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_HEXSTRIKE_SERVER,
                      help=f"HexStrike AI API server URL (default: {DEFAULT_HEXSTRIKE_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--transport", type=str, default="stdio", choices=["stdio", "sse", "streamable-http"],
                      help="MCP transport protocol (default: stdio for OpenClaw compatibility)")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("🔍 Debug logging enabled")

    logger.info(f"🚀 Starting HexStrike AI MCP Client v6.1 (with async progress)")
    logger.info(f"🔗 Connecting to: {args.server}")

    try:
        hexstrike_client = HexStrikeClient(args.server, args.timeout)

        health = hexstrike_client.check_health()
        if "error" in health:
            logger.warning(f"⚠️  Unable to connect to HexStrike AI API server at {args.server}: {health['error']}")
            logger.warning("🚀 MCP server will start, but tool execution may fail")
        else:
            logger.info(f"🎯 Successfully connected to HexStrike AI API server at {args.server}")
            logger.info(f"🏥 Server health status: {health['status']}")
            logger.info(f"📊 Version: {health.get('version', 'unknown')}")

        mcp = setup_mcp_server(hexstrike_client)
        logger.info("🚀 Starting HexStrike AI MCP server")
        logger.info("🤖 Ready to serve AI agents with enhanced cybersecurity capabilities")
        mcp.run(transport=args.transport)
    except Exception as e:
        logger.error(f"💥 Error starting MCP server: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()
