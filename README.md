![OpenSearch logo](https://github.com/opensearch-project/opensearch-py/raw/main/OpenSearch.svg)

- [OpenSearch MCP Server](https://github.com/opensearch-project/opensearch-mcp-server-py#opensearch-mcp-server)
- [Installing opensearch-mcp-server-py](https://github.com/opensearch-project/opensearch-mcp-server-py#installing-opensearch-mcp-server-py)
- [Available tools](https://github.com/opensearch-project/opensearch-mcp-server-py#available-tools)
- [User Guide](https://github.com/opensearch-project/opensearch-mcp-server-py#user-guide)
- [Contributing](https://github.com/opensearch-project/opensearch-mcp-server-py#contributing)
- [Code of Conduct](https://github.com/opensearch-project/opensearch-mcp-server-py#code-of-conduct)
- [License](https://github.com/opensearch-project/opensearch-mcp-server-py#license)
- [Copyright](https://github.com/opensearch-project/opensearch-mcp-server-py#copyright)

## OpenSearch MCP Server
**opensearch-mcp-server-py** is a Model Context Protocol (MCP) server for OpenSearch that enables AI assistants to interact with OpenSearch clusters. It provides a standardized interface for AI models to perform operations like searching indices, retrieving mappings, and managing shards through both stdio and Server-Sent Events (SSE) protocols.

**Key features:**
- Seamless integration with AI assistants and LLMs through the MCP protocol
- Support for both stdio and SSE server transports
- Built-in tools for common OpenSearch operations
- Easy integration with Claude Desktop and LangChain
- Secure authentication using basic auth or IAM roles

## Installing opensearch-mcp-server-py
Opensearch-mcp-server-py can be installed from [PyPI](https://pypi.org/project/opensearch-mcp-server-py/) via pip:
```
pip install opensearch-mcp-server-py
```

## Available tools
- ListIndexTool: Lists all indices in OpenSearch.
- IndexMappingTool: Retrieves index mapping and setting information for an index in OpenSearch.
- SearchIndexTool: Searches an index using a query written in query domain-specific language (DSL) in OpenSearch.
- GetShardsTool: Gets information about shards in OpenSearch.

> More tools coming soon. [Click here](DEVELOPER_GUIDE.md#contributing)

## User Guide
For detailed usage instructions, configuration options, and examples, please see the [User Guide](USER_GUIDE.md).

## Contributing
Interested in contributing? Check out our:
- [Development Guide](DEVELOPER_GUIDE.md#opensearch-mcp-server-py-developer-guide) - Setup your development environment
- [Contributing Guidelines](DEVELOPER_GUIDE.md#contributing) - Learn how to contribute

## Code of Conduct
This project has adopted the [Amazon Open Source Code of Conduct](CODE_OF_CONDUCT.md). For more information see the [Code of Conduct FAQ](https://aws.github.io/code-of-conduct-faq), or contact [opensource-codeofconduct@amazon.com](mailto:opensource-codeofconduct@amazon.com) with any additional questions or comments.

## License
This project is licensed under the [Apache v2.0 License](LICENSE.txt).

## Copyright
Copyright 2020-2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.