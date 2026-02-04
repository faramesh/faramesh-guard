"""
IPC Decision Socket - Unix domain socket for local inter-process communication.

This module provides a high-performance local socket interface for
Guard decisions, avoiding HTTP overhead for local clients.
"""

import asyncio
import json
import logging
import os
import signal
import struct
from dataclasses import dataclass
from typing import Dict, Any, Optional, Callable, Awaitable
from pathlib import Path

logger = logging.getLogger("service.ipc_socket")

# Default socket path
DEFAULT_SOCKET_PATH = "/tmp/faramesh-guard.sock"

# Message format: 4-byte length prefix + JSON payload
HEADER_FORMAT = "!I"  # Network byte order, unsigned int
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB max message


@dataclass
class IPCRequest:
    """Represents an IPC request."""

    request_id: str
    action: str  # execute, authorize, pending, approve, deny, etc.
    payload: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict) -> "IPCRequest":
        return cls(
            request_id=data.get("request_id", ""),
            action=data.get("action", ""),
            payload=data.get("payload", {}),
        )

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "payload": self.payload,
        }


@dataclass
class IPCResponse:
    """Represents an IPC response."""

    request_id: str
    success: bool
    data: Dict[str, Any]
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "request_id": self.request_id,
            "success": self.success,
            "data": self.data,
            "error": self.error,
        }


# Type for request handlers
RequestHandler = Callable[[IPCRequest], Awaitable[IPCResponse]]


class IPCDecisionSocket:
    """
    Unix domain socket server for Guard IPC.

    Provides:
    - Low-latency local communication
    - Binary framing with length prefix
    - JSON message format
    - Concurrent connection handling
    """

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        max_connections: int = 100,
    ):
        self.socket_path = socket_path
        self.max_connections = max_connections
        self.server: Optional[asyncio.AbstractServer] = None
        self.handlers: Dict[str, RequestHandler] = {}
        self.connections: Dict[str, asyncio.StreamWriter] = {}
        self._running = False

        # Register built-in handlers
        self._register_builtin_handlers()

    def _register_builtin_handlers(self) -> None:
        """Register built-in action handlers."""
        self.register_handler("ping", self._handle_ping)
        self.register_handler("health", self._handle_health)
        self.register_handler("capabilities", self._handle_capabilities)

    async def _handle_ping(self, request: IPCRequest) -> IPCResponse:
        """Handle ping request."""
        return IPCResponse(
            request_id=request.request_id,
            success=True,
            data={"pong": True},
        )

    async def _handle_health(self, request: IPCRequest) -> IPCResponse:
        """Handle health check request."""
        return IPCResponse(
            request_id=request.request_id,
            success=True,
            data={
                "status": "healthy",
                "socket_path": self.socket_path,
                "connections": len(self.connections),
            },
        )

    async def _handle_capabilities(self, request: IPCRequest) -> IPCResponse:
        """Handle capabilities request."""
        return IPCResponse(
            request_id=request.request_id,
            success=True,
            data={
                "actions": list(self.handlers.keys()),
                "max_message_size": MAX_MESSAGE_SIZE,
                "protocol": "json-lp",  # JSON with length prefix
            },
        )

    def register_handler(self, action: str, handler: RequestHandler) -> None:
        """Register a handler for an action type."""
        self.handlers[action] = handler
        logger.debug(f"Registered IPC handler: {action}")

    async def start(self) -> None:
        """Start the IPC socket server."""
        # Remove existing socket file
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        # Ensure directory exists
        Path(self.socket_path).parent.mkdir(parents=True, exist_ok=True)

        # Start server
        self.server = await asyncio.start_unix_server(
            self._handle_connection,
            path=self.socket_path,
        )

        # Set permissions (owner read/write only for security)
        os.chmod(self.socket_path, 0o600)

        self._running = True
        logger.info(f"IPC socket server started: {self.socket_path}")

        # Serve until stopped
        async with self.server:
            await self.server.serve_forever()

    async def stop(self) -> None:
        """Stop the IPC socket server."""
        self._running = False

        # Close all connections
        for conn_id, writer in list(self.connections.items()):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self.connections.clear()

        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

        # Remove socket file
        if os.path.exists(self.socket_path):
            os.unlink(self.socket_path)

        logger.info("IPC socket server stopped")

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a client connection."""
        conn_id = f"{id(writer)}"
        self.connections[conn_id] = writer

        logger.debug(f"New IPC connection: {conn_id}")

        try:
            while self._running:
                # Read message
                request_data = await self._read_message(reader)
                if request_data is None:
                    break

                # Parse request
                try:
                    request = IPCRequest.from_dict(request_data)
                except Exception as e:
                    response = IPCResponse(
                        request_id=request_data.get("request_id", ""),
                        success=False,
                        data={},
                        error=f"Invalid request: {e}",
                    )
                    await self._write_message(writer, response.to_dict())
                    continue

                # Handle request
                response = await self._dispatch_request(request)

                # Send response
                await self._write_message(writer, response.to_dict())

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"IPC connection error: {e}")
        finally:
            # Clean up
            self.connections.pop(conn_id, None)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug(f"IPC connection closed: {conn_id}")

    async def _read_message(
        self,
        reader: asyncio.StreamReader,
    ) -> Optional[Dict]:
        """Read a length-prefixed JSON message."""
        try:
            # Read header
            header = await reader.readexactly(HEADER_SIZE)
            length = struct.unpack(HEADER_FORMAT, header)[0]

            # Validate length
            if length > MAX_MESSAGE_SIZE:
                logger.warning(f"Message too large: {length} bytes")
                return None

            # Read payload
            payload = await reader.readexactly(length)

            # Parse JSON
            return json.loads(payload.decode("utf-8"))

        except asyncio.IncompleteReadError:
            return None
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in IPC message: {e}")
            return None

    async def _write_message(
        self,
        writer: asyncio.StreamWriter,
        data: Dict,
    ) -> None:
        """Write a length-prefixed JSON message."""
        # Encode payload
        payload = json.dumps(data).encode("utf-8")

        # Write header + payload
        header = struct.pack(HEADER_FORMAT, len(payload))
        writer.write(header + payload)
        await writer.drain()

    async def _dispatch_request(self, request: IPCRequest) -> IPCResponse:
        """Dispatch request to appropriate handler."""
        handler = self.handlers.get(request.action)

        if handler is None:
            return IPCResponse(
                request_id=request.request_id,
                success=False,
                data={},
                error=f"Unknown action: {request.action}",
            )

        try:
            return await handler(request)
        except Exception as e:
            logger.error(f"Handler error for {request.action}: {e}")
            return IPCResponse(
                request_id=request.request_id,
                success=False,
                data={},
                error=str(e),
            )

    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running

    def get_stats(self) -> Dict:
        """Get server statistics."""
        return {
            "running": self._running,
            "socket_path": self.socket_path,
            "connections": len(self.connections),
            "handlers": list(self.handlers.keys()),
        }


class IPCClient:
    """
    Client for connecting to Guard IPC socket.

    Provides:
    - Async connection management
    - Request/response correlation
    - Automatic reconnection
    """

    def __init__(
        self,
        socket_path: str = DEFAULT_SOCKET_PATH,
        timeout: float = 5.0,
    ):
        self.socket_path = socket_path
        self.timeout = timeout
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self._request_counter = 0

    async def connect(self) -> bool:
        """Connect to IPC socket."""
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=self.timeout,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to connect to IPC socket: {e}")
            return False

    async def disconnect(self) -> None:
        """Disconnect from IPC socket."""
        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception:
                pass
        self.reader = None
        self.writer = None

    async def request(
        self,
        action: str,
        payload: Dict[str, Any] = None,
    ) -> IPCResponse:
        """Send a request and wait for response."""
        if not self.writer or not self.reader:
            if not await self.connect():
                return IPCResponse(
                    request_id="",
                    success=False,
                    data={},
                    error="Not connected",
                )

        # Generate request ID
        self._request_counter += 1
        request_id = f"req-{self._request_counter}"

        request = IPCRequest(
            request_id=request_id,
            action=action,
            payload=payload or {},
        )

        try:
            # Send request
            await self._write_message(request.to_dict())

            # Read response
            response_data = await asyncio.wait_for(
                self._read_message(),
                timeout=self.timeout,
            )

            if response_data is None:
                return IPCResponse(
                    request_id=request_id,
                    success=False,
                    data={},
                    error="No response",
                )

            return IPCResponse(
                request_id=response_data.get("request_id", ""),
                success=response_data.get("success", False),
                data=response_data.get("data", {}),
                error=response_data.get("error"),
            )

        except asyncio.TimeoutError:
            return IPCResponse(
                request_id=request_id,
                success=False,
                data={},
                error="Request timeout",
            )
        except Exception as e:
            return IPCResponse(
                request_id=request_id,
                success=False,
                data={},
                error=str(e),
            )

    async def _write_message(self, data: Dict) -> None:
        """Write a length-prefixed JSON message."""
        payload = json.dumps(data).encode("utf-8")
        header = struct.pack(HEADER_FORMAT, len(payload))
        self.writer.write(header + payload)
        await self.writer.drain()

    async def _read_message(self) -> Optional[Dict]:
        """Read a length-prefixed JSON message."""
        try:
            header = await self.reader.readexactly(HEADER_SIZE)
            length = struct.unpack(HEADER_FORMAT, header)[0]

            if length > MAX_MESSAGE_SIZE:
                return None

            payload = await self.reader.readexactly(length)
            return json.loads(payload.decode("utf-8"))
        except Exception:
            return None

    async def ping(self) -> bool:
        """Ping the server."""
        response = await self.request("ping")
        return response.success

    async def health(self) -> Dict:
        """Get server health."""
        response = await self.request("health")
        return response.data if response.success else {}

    async def execute(
        self,
        tool_name: str,
        args: Dict[str, Any],
        agent_id: str = "ipc-client",
    ) -> IPCResponse:
        """Execute an action through Guard."""
        return await self.request(
            "execute",
            {
                "tool_name": tool_name,
                "args": args,
                "agent_id": agent_id,
            },
        )


# Singleton server instance
_ipc_server: Optional[IPCDecisionSocket] = None


def get_ipc_server(socket_path: str = DEFAULT_SOCKET_PATH) -> IPCDecisionSocket:
    """Get or create singleton IPC server."""
    global _ipc_server
    if _ipc_server is None:
        _ipc_server = IPCDecisionSocket(socket_path=socket_path)
    return _ipc_server
