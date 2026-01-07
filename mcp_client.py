import requests
import json
import asyncio
from loguru import logger

class MCPClient:
    """
    Client for the Model Context Protocol (MCP).
    Enables 'Context-Aware' commerce by connecting to Merchant Intelligence Servers.
    """
    
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    async def connect_and_query(self, mcp_url: str, query: str, context_filter: dict = None) -> str:
        """
        Connects to a Merchant's MCP Server (SSE/HTTP) and asks a question.
        e.g. "Do you have the H100 in stock for immediate delivery?"
        """
        logger.info(f"🔌 [MCP] Connecting to Context Server: {mcp_url}")
        
        # 1. Discover capabilities (Standard MCP handshake)
        # In a full impl, we'd negotiate capabilities. 
        # Here we assume a simple 'prompt/query' tool is exposed.
        
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "query_product_context", # Standard commerce tool
                "arguments": {
                    "query": query,
                    "filter": context_filter or {}
                }
            },
            "id": 1
        }
        
        try:
            # Assuming HTTP Transport for simple query/response (stateless mode)
            # Real MCP uses persistent connections, but stateless HTTP is common for public read-only nodes.
            resp = requests.post(f"{mcp_url}/messages", json=payload, timeout=5.0)
            resp.raise_for_status()
            
            data = resp.json()
            if "error" in data:
                 logger.warning(f"⚠️ [MCP] Merchant replied with error: {data['error']}")
                 return None
                 
            content = data.get("result", {}).get("content", [])
            # Extract text from content blocks
            text_context = "\n".join([c.get("text", "") for c in content if c.get("type") == "text"])
            
            logger.info(f"🧠 [MCP] Context Received: {text_context[:100]}...")
            return text_context
            
        except Exception as e:
            logger.error(f"❌ [MCP] Connection Failed: {e}")
            return None
