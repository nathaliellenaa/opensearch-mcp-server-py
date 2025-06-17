# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import yaml
import aiohttp
import json
import os
from pydantic import BaseModel, create_model
from typing import Dict, Any, List
from mcp.types import TextContent
from opensearchpy import OpenSearch
from .tools import TOOL_REGISTRY

# Constants
BASE_URL = "https://raw.githubusercontent.com/opensearch-project/opensearch-api-specification/refs/heads/main/spec/namespaces"
SPEC_FILES = ["cluster.yaml", "_core.yaml"]
SUPPORTED_OPERATIONS = ["msearch", "explain", "count", "cluster.health"]

async def fetch_github_spec(file_name: str) -> Dict:
    """Fetch OpenSearch API specification from GitHub asynchronously."""
    url = f"{BASE_URL}/{file_name}"
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            # Raise exception for HTTP errors
            response.raise_for_status()
            # Parse YAML into Python dict
            return yaml.safe_load(await response.text())

def group_endpoints_by_operation(paths: Dict[str, Dict]) -> Dict[str, List[Dict]]:
    """Group endpoints by their x-operation-group."""
    grouped_ops = {}
    for path, methods in paths.items():
        for method, details in methods.items():
            op_group = details.get('x-operation-group')
            # TODO: Remove hard-coded logic once we have the tool filtering feature
            if op_group in SUPPORTED_OPERATIONS:
                grouped_ops.setdefault(op_group, []).append({
                    'path': path,
                    'method': method,
                    'details': details
                })
    return grouped_ops

def extract_parameters(endpoints: list[dict]) -> tuple[dict[str, dict], set]:
    """Extract parameters from endpoints."""
    # Add opensearch_url parameter to all tools
    all_parameters = {
        'opensearch_url': {
            "default": os.getenv("OPENSEARCH_URL", ""),
            "title": "Opensearch Url",
            "type": "string"
        }
    }
    path_parameters = set()

    # Track which path parameters appear in which endpoints
    param_to_endpoints = {}

    # Extract parameters from endpoints
    for i, endpoint in enumerate(endpoints):
        path = endpoint['path']
        details = endpoint['details']
        
        # Extract path parameters (parameters in the URL path like {index})
        for part in path.split('/'):
            if part.startswith('{') and part.endswith('}'):
                param_name = part[1:-1]
                path_parameters.add(param_name)
                all_parameters[param_name] = {
                    "title": param_name.title(),
                    "type": "string",
                }
                param_to_endpoints.setdefault(param_name, set()).add(i)
        
        # Add parameters from the endpoint details
        for param in details.get('parameters', []):
            param_name = param.get('name')
            if param_name and param_name not in all_parameters:
                param_schema = param.get('schema', {})
                all_parameters[param_name] = {
                    "title": param_name.title(),
                    "type": param_schema.get('type', 'string'),
                    "description": param.get('description', ''),
                }

        # Add body parameter if needed
        if 'requestBody' in details:
            all_parameters['body'] = {
                "title": "Body",
                "description": "Request body",
            }

    # Mark parameters as required if they appear in all endpoints
    for param, endpoint_indices in param_to_endpoints.items():
        if len(endpoint_indices) == len(endpoints):
            all_parameters[param]["required"] = True
    
    # Mark body as required for ExplainTool and MsearchTool
    # TODO: Remove hard-coded logic once we found a better way to determine required request body
    op_group = endpoints[0]['details'].get('x-operation-group', '')
    if op_group in ['explain', 'msearch'] and 'body' in all_parameters:
        all_parameters['body']["required"] = True
    
    return all_parameters, path_parameters

def process_body(body: Any, tool_name: str) -> Any:
    """Process request body based on tool type and format."""
    if body is None:
        return None

    # Handle string body
    if isinstance(body, str):
        # Multi search tool (msearch) requires request body to be in NDJSON format
        if tool_name == "Msearch":
            try:
                # Check if it's a JSON array string
                parsed = json.loads(body)
                if isinstance(parsed, list):
                    # Convert JSON array to NDJSON format
                    ndjson = ""
                    for item in parsed:
                        ndjson += json.dumps(item) + "\n"
                    return ndjson
                return body if body.endswith("\n") else body + "\n"
            except json.JSONDecodeError:
                # If not valid JSON, treat as NDJSON
                return body if body.endswith("\n") else body + "\n"
        
        # For other tools, parse JSON string to object
        if body.strip():
            try:
                return json.loads(body)
            except json.JSONDecodeError:
                raise ValueError("Invalid JSON in body parameter")
        return None
    return body

def select_endpoint(endpoints: list[dict], params: dict) -> dict:
    """Select the most appropriate endpoint based on parameters."""
    # Try to find endpoint matching all parameters
    for endpoint in endpoints:
        path_params = [p[1:-1] for p in endpoint['path'].split('/') 
                      if p.startswith('{') and p.endswith('}')]
        if all(param in params for param in path_params):
            return endpoint
    
    # Fall back to simplest endpoint
    return next((ep for ep in endpoints 
                if not any('{' in p for p in ep['path'].split('/'))), 
               endpoints[0])

def generate_tool_from_group(tool_name: str, endpoints: List[Dict], client: OpenSearch) -> Dict[str, Any]:
    """Generate a single tool from a group of related endpoints."""
    # Use the description from the first endpoint in the group
    details = endpoints[0]['details']
    description = details.get('description', '')

    # Extract version information
    min_version = details.get('x-version-added', '0.0.0')
    max_version = details.get('x-version-deprecated', '99.99.99')

    all_parameters, path_parameters = extract_parameters(endpoints)

    # Create Pydantic model for arguments
    field_definitions = {
        name: (Any if name == 'body' else str, info.get('default'))
        for name, info in all_parameters.items()
    }
    args_model = create_model(f"{tool_name}Args", **field_definitions)

    # Create the tool function that will execute the OpenSearch API
    async def tool_func(params: BaseModel) -> list[TextContent]:
        try:
            params_dict = params.dict() if hasattr(params, 'dict') else {}
            
            # Handle opensearch_url
            opensearch_url = params_dict.pop('opensearch_url', None)
            request_client = client
            if opensearch_url:
                from opensearch.client import initialize_client
                try:
                    request_client = initialize_client(opensearch_url)
                except Exception as e:
                    return [TextContent(
                        type="text",
                        text=f"Error initializing OpenSearch client: {str(e)}"
                    )]

            # Process body and select endpoint
            body = process_body(params_dict.pop('body', None), tool_name)
            selected_endpoint = select_endpoint(endpoints, params_dict)
                    
            # Prepare request
            formatted_path = selected_endpoint['path']
            for param_name in path_parameters:
                if param_name in params_dict:
                    formatted_path = formatted_path.replace(f"{{{param_name}}}", str(params_dict[param_name]))
                    del params_dict[param_name]
            method = selected_endpoint['method'].upper()  # HTTP method (GET, POST, etc.)
            api_path = f"/{formatted_path.lstrip('/')}"  # Ensure path starts with /
            
            # Execute the OpenSearch API request
            response = request_client.transport.perform_request(
                method=method,
                url=api_path,
                params=params_dict,
                body=body
            )
            
            return [TextContent(
                type="text",
                text=json.dumps(response) if not isinstance(response, str) else response
            )]

        except Exception as e:
            return [TextContent(
                type="text",
                text=f"Error: {str(e)}"
            )]

    # Create input schema with required fields
    input_schema = {
        "type": "object",
        "title": f"{tool_name}Args",
        "properties": all_parameters
    }
    
    # Add required fields
    required_fields = [name for name, schema in all_parameters.items() if schema.get('required')]
    if required_fields:
        input_schema["required"] = required_fields
    
    return {
        'description': description,
        'input_schema': input_schema,
        'function': tool_func,
        'args_model': args_model,
        'min_version': min_version,
        'max_version': max_version
    }

async def generate_tools_from_openapi(client: OpenSearch) -> Dict[str, Dict[str, Any]]:
    """Generate tools from OpenSearch API specification and append to TOOL_REGISTRY."""
    try:
        for spec_file in SPEC_FILES:
            spec = await fetch_github_spec(spec_file)
            grouped_ops = group_endpoints_by_operation(spec.get("paths", {}))

            # Generate tools for each operation group
            for group_name, endpoints in grouped_ops.items():
                base_name = ''.join(part.title() for part in group_name.split('.'))
                tool_name = f"{base_name.replace('_', '')}Tool"
                TOOL_REGISTRY[tool_name] = generate_tool_from_group(base_name, endpoints, client)

    except Exception as e:
        print(f"Error generating tools: {e}")

    return TOOL_REGISTRY