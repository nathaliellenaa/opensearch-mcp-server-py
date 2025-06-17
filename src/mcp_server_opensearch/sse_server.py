# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import logging
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Mount, Route
from starlette.responses import Response
from mcp.server.sse import SseServerTransport
from mcp.server import Server
from mcp.types import TextContent, Tool
from tools.common import get_enabled_tools
from opensearch.helper import get_opensearch_version
from tools.tool_generator import generate_tools_from_openapi
from opensearch.client import initialize_client

async def create_mcp_server() -> Server:
    server = Server("opensearch-mcp-server")
    opensearch_url = os.getenv("OPENSEARCH_URL", "https://localhost:9200")

    # Call tool generator
    await generate_tools_from_openapi(initialize_client(opensearch_url))

    # Filter all tools by version
    version = get_opensearch_version(opensearch_url)
    enabled_tools = get_enabled_tools(version)
    logging.info(f"Connected OpenSearch version: {version}")
    logging.info(f"Enabled tools: {list(enabled_tools.keys())}")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tools = []
        for tool_name, tool_info in enabled_tools.items():
            tools.append(
                Tool(
                    name=tool_name,
                    description=tool_info["description"],
                    inputSchema=tool_info["input_schema"],
                )
            )
        return tools

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        tool = enabled_tools.get(name)
        if not tool:
            raise ValueError(f"Unknown or disabled tool: {name}")
        parsed = tool["args_model"](**arguments)
        return await tool["function"](parsed)

    return server


class MCPStarletteApp:
    def __init__(self, mcp_server: Server):
        self.mcp_server = mcp_server
        self.sse = SseServerTransport("/messages/")

    async def handle_sse(self, request: Request) -> None:
        async with self.sse.connect_sse(
            request.scope,
            request.receive,
            request._send,
        ) as (read_stream, write_stream):
            await self.mcp_server.run(
                read_stream,
                write_stream,
                self.mcp_server.create_initialization_options(),
            )

        # Done to prevent 'NoneType' errors. For more details: https://github.com/modelcontextprotocol/python-sdk/blob/main/src/mcp/server/sse.py#L33-L37
        return Response()

    async def handle_health(self, request: Request) -> Response:
        return Response("OK", status_code=200)

    def create_app(self) -> Starlette:
        return Starlette(
            routes=[
                Route("/sse", endpoint=self.handle_sse, methods=["GET"]),
                Route("/health", endpoint=self.handle_health, methods=["GET"]),
                Mount("/messages/", app=self.sse.handle_post_message),
            ]
        )


async def serve(host: str = "0.0.0.0", port: int = 9900) -> None:
    mcp_server = await create_mcp_server()
    app_handler = MCPStarletteApp(mcp_server)
    app = app_handler.create_app()

    config = uvicorn.Config(
        app=app,
        host=host,
        port=port,
    )
    server = uvicorn.Server(config)
    await server.serve()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run OpenSearch MCP SSE-based server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=9900, help="Port to listen on")
    args = parser.parse_args()

    import asyncio

    asyncio.run(serve(host=args.host, port=args.port))
