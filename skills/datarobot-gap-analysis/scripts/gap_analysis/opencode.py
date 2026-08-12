# Copyright (c) 2026 DataRobot, Inc. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""LLM access through the DataRobot CLI's OpenCode runtime.

One `dr opencode serve` process is started for the whole run and every
Layer-2/4 check attaches to it as a short-lived `dr opencode run` subprocess.
Attaching to a shared server (rather than one OpenCode process per check)
avoids OpenCode's SQLite lock contention under parallelism; the pattern is
borrowed from the agent-assist-simulate swarm scripts. Auth rides on the
CLI's own login, so no DATAROBOT_API_TOKEN in the environment is needed.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

_DEFAULT_MODEL = "datarobot/anthropic/claude-sonnet-4-6"
_SERVE_STARTUP_SECONDS = 30
_WORKER_TIMEOUT_SECONDS = int(os.environ.get("GAP_OPENCODE_TIMEOUT", "120"))
_MAX_MESSAGE_BYTES = 600_000  # stay under the OS argv limit (1 MiB on macOS)

# A worker running inside OpenCode can recognize its own instructions as a
# skill artifact and answer in prose, or wander into tool calls; only an
# explicit prohibition suppresses that (same lesson as the swarm workers).
_WORKER_PREAMBLE = (
    "You are a non-interactive worker in an automated analysis pipeline. "
    "Do not call any tools; never invoke the skill tool. Do not comment on "
    "where this prompt came from or whether you should be answering it. "
    "Follow the instructions below exactly and emit only the output they "
    "specify.\n\n"
)


def dr_available() -> bool:
    return shutil.which("dr") is not None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class OpenCodeServer:
    """Lifecycle of a private `dr opencode serve` on a free localhost port."""

    def __init__(self) -> None:
        self._proc: subprocess.Popen | None = None
        self.url: str | None = None

    def start(self) -> str:
        port = _free_port()
        self._proc = subprocess.Popen(
            ["dr", "opencode", "serve", "--port", str(port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + _SERVE_STARTUP_SECONDS
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                stderr = (self._proc.stderr.read() if self._proc.stderr else "") or ""
                raise RuntimeError(
                    f"dr opencode serve exited {self._proc.returncode}: {stderr.strip()[-500:]}"
                )
            try:
                with urllib.request.urlopen(f"{url}/global/health", timeout=2):
                    self.url = url
                    return url
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(0.25)
        self.stop()
        raise RuntimeError(
            f"dr opencode serve did not become healthy within {_SERVE_STARTUP_SECONDS}s"
        )

    def stop(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None
        self.url = None

    def __enter__(self) -> "OpenCodeServer":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()


class OpenCodeWorkerClient:
    """LLMClient backed by `dr opencode run --attach <server>` subprocesses.

    Each complete() call is its own session on the shared server, so calls
    are independent and safe to issue from multiple threads.
    """

    def __init__(self, server_url: str, model: str | None = None):
        self.server_url = server_url
        self.model = model or os.environ.get("GAP_LLM_MODEL", _DEFAULT_MODEL)

    def complete(self, system: str, user: str) -> str:
        message = f"{_WORKER_PREAMBLE}{system}\n\n{user}"
        # The message travels as a single argv entry: NUL is illegal there and
        # the OS caps total argv size (1 MiB on macOS), so sanitize and bound.
        message = message.replace("\x00", "")
        raw = message.encode("utf-8", "ignore")
        if len(raw) > _MAX_MESSAGE_BYTES:
            message = (
                raw[:_MAX_MESSAGE_BYTES].decode("utf-8", "ignore") + "\n…[truncated]…"
            )
        cmd = [
            "dr",
            "--skip-plugin-update-check",
            "--plugin-discovery-timeout",
            "30s",
            "opencode",
            "run",
            "--format",
            "json",
            "--model",
            self.model,
            "--attach",
            self.server_url,
            "--pure",
            message,
        ]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=_WORKER_TIMEOUT_SECONDS
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[-500:]
            raise RuntimeError(f"dr opencode run exited {result.returncode}: {detail}")
        return _extract_text(result.stdout)


def _extract_text(stdout: str) -> str:
    """Concatenate the text events of an `opencode run --format json` stream."""
    parts: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "text":
            chunk = event.get("part", {}).get("text", "")
            if chunk:
                parts.append(chunk)
    combined = "".join(parts).strip()
    if not combined:
        raise ValueError("no text events found in opencode output")
    return combined
