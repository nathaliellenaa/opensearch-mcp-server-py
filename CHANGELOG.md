# CHANGELOG

Inspired from [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased]

### Added

### Removed

### Fixed
- Fix endpoint selection bug in ClusterHealthTool and CountTool ([#59](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/59))

### Security

## [Released 0.2]
### Added
- Add OpenSearch URl as an optional parameter for tool calls ([#20](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/20))
- Add CI to run unit tests ([#22](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/22))
- Add support for AWS OpenSearch serverless ([#31](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/31))
- Add filtering tools based on OpenSearch version compatibility defined in TOOL_REGISTRY ([#32](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/32))
- Add `ClusterHealthTool`, `CountTool`,  `MsearchTool`, and `ExplainTool` through OpenSearch API specification ([#33](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/33))
- Add support for Multiple OpenSearch cluster Connectivity ([#45](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/45))
- Add tool filter feature [#46](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/46)
- Support Streamable HTTP Protocol [#47](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/47)
- Add `OPENSEARCH_SSL_VERIFY` environment variable ([#40](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/40))
### Removed

### Fixed
- Fix AWS auth requiring `AWS_REGION` environment variable to be set, will now support using region set via `~/.aws/config` ([#28](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/28))
- Fix OpenSearch client to use refreshable credentials ([#13](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/13))
- fix publish release ci and bump version on main ([#49](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/49))
- fix OpenAPI tools schema, handle NDJSON ([#52](https://github.com/opensearch-project/opensearch-mcp-server-py/pull/52))
### Security
