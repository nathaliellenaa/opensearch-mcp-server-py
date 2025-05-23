![OpenSearch logo](https://github.com/opensearch-project/opensearch-py/raw/main/OpenSearch.svg)

# OpenSearch-mcp-server-py User Guide

## Installation

Install from PyPI:
```
pip install opensearch-mcp-server-py
```

## Configuration
### Authentication Methods:
- **Basic Authentication**
```
export OPENSEARCH_URL="<your_opensearch_domain_url>"
export OPENSEARCH_USERNAME="<your_opensearch_domain_username>"
export OPENSEARCH_PASSWORD="<your_opensearch_domain_password>"
```

- **IAM Role Authentication**
```
export OPENSEARCH_URL="<your_opensearch_domain_url>"
export AWS_REGION="<your_aws_region>"
export AWS_ACCESS_KEY_ID="<your_aws_access_key>"
export AWS_SECRET_ACCESS_KEY="<your_aws_secret_access_key>"
export AWS_SESSION_TOKEN="<your_aws_session_token>"
```

## Running the Server
```
# Stdio Server
python -m mcp_server_opensearch

# SSE Server
python -m mcp_server_opensearch --transport sse
```

## Claude Desktop Integration
- **Using the Published [PyPI Package](https://pypi.org/project/opensearch-mcp-server-py/) (Recommended)**
```
{
    "mcpServers": {
        "opensearch-mcp-server": {
            "command": "uvx",
            "args": [
                "opensearch-mcp-server-py"
            ],
            "env": {
                // Required
                "OPENSEARCH_URL": "<your_opensearch_domain_url>",

                // For Basic Authentication
                "OPENSEARCH_USERNAME": "<your_opensearch_domain_username>",
                "OPENSEARCH_PASSWORD": "<your_opensearch_domain_password>",

                // For IAM Role Authentication
                "AWS_REGION": "<your_aws_region>",
                "AWS_ACCESS_KEY_ID": "<your_aws_access_key>",
                "AWS_SECRET_ACCESS_KEY": "<your_aws_secret_access_key>",
                "AWS_SESSION_TOKEN": "<your_aws_session_token>"
            }
        }
    }
}
```

- **Using the Installed Package (via pip):**
```
{
    "mcpServers": {
        "opensearch-mcp-server": {
            "command": "python",  // Or full path to python with PyPI package installed
            "args": [
                "-m",
                "mcp_server_opensearch"
            ],
            "env": {
                // Required
                "OPENSEARCH_URL": "<your_opensearch_domain_url>",

                // For Basic Authentication
                "OPENSEARCH_USERNAME": "<your_opensearch_domain_username>",
                "OPENSEARCH_PASSWORD": "<your_opensearch_domain_password>",

                // For IAM Role Authentication
                "AWS_REGION": "<your_aws_region>",
                "AWS_ACCESS_KEY_ID": "<your_aws_access_key>",
                "AWS_SECRET_ACCESS_KEY": "<your_aws_secret_access_key>",
                "AWS_SESSION_TOKEN": "<your_aws_session_token>"
            }
        }
    }
}
```

## LangChain Integration
The OpenSearch MCP server can be easily integrated with LangChain using the SSE server transport

### Prerequisites
1. Install required packages
```
pip install langchain langchain-mcp-adapters langchain-openai
```
2. Set up OpenAI API key
```
export OPENAI_API_KEY="<your-openai-key>"
```
3. Ensure OpenSearch MCP server is running in SSE mode
```
python -m mcp_server_opensearch --transport sse
```

### Example Integration Script
``` python 
import asyncio
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_openai import ChatOpenAI
from langchain.agents import AgentType, initialize_agent

# Initialize LLM (can use any LangChain-compatible LLM)
model = ChatOpenAI(model="gpt-4o")

async def main():
    # Connect to MCP server and create agent
    async with MultiServerMCPClient({
        "opensearch-mcp-server": {
            "transport": "sse",
            "url": "http://localhost:9900/sse",  # SSE server endpoint
            "headers": {
                "Authorization": "Bearer secret-token",
            }
        }
    }) as client:
        tools = client.get_tools()
        agent = initialize_agent(
            tools=tools,
            llm=model,
            agent=AgentType.OPENAI_FUNCTIONS,
            verbose=True,  # Enables detailed output of the agent's thought process
        )

        # Example query
        await agent.ainvoke({"input": "List all indices"})

if __name__ == "__main__":
    asyncio.run(main())
```
**Notes:**
- The script is compatible with any LLM that integrates with LangChain and supports tool calling
- Make sure the OpenSearch MCP server is running before executing the script
- Configure authentication and environment variables as needed