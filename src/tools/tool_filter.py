# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import re
import os
import json
import yaml
import logging
from .tool_params import baseToolArgs
from .tools import TOOL_REGISTRY
from .utils import is_tool_compatible
from opensearch.helper import get_opensearch_version


def parse_comma_separated(text, separator=","):
    """Parse a comma-separated string into a list of trimmed values."""
    if not text:
        return []
    return [item.strip() for item in text.split(separator) if item.strip()]

def load_yaml_config(filter_path):
    """Load and validate YAML configuration file."""
    if not filter_path:
        return None
    try:
        with open(filter_path, 'r') as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict):
            logging.warning(f"Invalid tool filter configuration in {filter_path}")
            return None
        return config
    except Exception as e:
        logging.error(f"Error loading filter config: {str(e)}")
        return None

def process_categories(category_list, category_to_tools):
    """Process categories and return tools from those categories."""
    tools = []
    for category in category_list:
        if category in category_to_tools:
            tools.extend(category_to_tools[category])
        else:
            logging.warning(f"Category '{category}' not found in tool categories")
    return tools

def process_regex_patterns(regex_list, tool_names):
    """Process regex patterns and return matching tool names."""
    matching_tools = []
    for regex in regex_list:
        for tool_name in tool_names:
            if re.match(regex, tool_name, re.IGNORECASE):
                matching_tools.append(tool_name)
    return matching_tools

def validate_tools(tool_list, registry_lookup, source_name):
    """Validate tools against registry and return valid tools."""
    valid_tools = set()
    for tool in tool_list:
        tool_lower = tool.lower()
        if tool_lower in registry_lookup:
            valid_tools.add(tool_lower)
        else:
            logging.warning(f"Ignoring invalid tool from '{source_name}': '{tool}'")
    return valid_tools

def apply_read_write_filters(registry, allow_read, allow_write):
    """Apply read/write filters to the registry."""
    if allow_read and allow_write:
        logging.warning("Both allow_read and allow_write are set to True. This is not recommended.")
        return

    if allow_read or allow_write:
        for tool_name in list(registry.keys()):
            http_methods = registry[tool_name].get('http_methods', [])
            if (allow_read and 'GET' not in http_methods) or \
               (allow_write and 'GET' in http_methods):
                registry.pop(tool_name, None)

def process_tool_filter(
        enabled_tools: str = None,
        disabled_tools: str = None,
        tool_categories: str = None,
        enabled_categories: str = None,
        disabled_categories: str = None,
        enabled_tools_regex: str = None,
        disabled_tools_regex: str = None,
        allow_read: bool = None,
        allow_write: bool = None,
        filter_path: str = None
    ) -> None:
    """Process tool filter configuration from a YAML file and environment variables.
    
    Args:
        enabled_tools: Comma-separated list of enabled tool names
        disabled_tools: Comma-separated list of disabled tool names
        tool_categories: JSON string defining tool categories, e.g. '{"critical":["ListIndexTool","MsearchTool"]}'
        enabled_categories: Comma-separated list of enabled category names
        disabled_categories: Comma-separated list of disabled category names
        enabled_tools_regex: Comma-separated list of enabled tools regex
        disabled_tools_regex: Comma-separated list of disabled tools regex
        allow_read: If True, keep only tools with GET methods
        allow_write: If True, keep only tools without GET methods
        filter_path: Path to the YAML filter configuration file
    """
    try:
        # Create case-insensitive lookup
        tool_registry_lower = {k.lower(): k for k in TOOL_REGISTRY.keys()}
        
        # Initialize collections
        category_to_tools = {}
        enabled_tools_list = []
        disabled_tools_list = []
        enabled_category_list = []
        disabled_category_list = []
        enabled_tools_regex_list = []
        disabled_tools_regex_list = []

        # Process YAML config file if provided
        config = load_yaml_config(filter_path)
        if config:
            # Extract configuration values
            category_to_tools.update(config.get('tool_category', {}))
            tool_filters = config.get('tool_filters', {})
            
            # Get lists from config
            enabled_tools_list = tool_filters.get('enabled_tools', [])
            disabled_tools_list = tool_filters.get('disabled_tools', [])
            enabled_category_list = tool_filters.get('enabled_categories', [])
            disabled_category_list = tool_filters.get('disabled_categories', [])
            enabled_tools_regex_list = tool_filters.get('enabled_tools_regex', [])
            disabled_tools_regex_list = tool_filters.get('disabled_tools_regex', [])
            
            # Get settings
            settings = tool_filters.get('settings', {})
            if settings:
                allow_read = settings.get('allow_read', allow_read)
                allow_write = settings.get('allow_write', allow_write)

        # Process environment variables
        if tool_categories:
            try:
                category_to_tools.update(json.loads(tool_categories) if isinstance(tool_categories, str) else {})
            except json.JSONDecodeError:
                logging.warning(f"Invalid JSON in tool_categories: {tool_categories}")
        
        # Parse comma-separated strings from environment variables
        if enabled_tools:
            enabled_tools_list.extend(parse_comma_separated(enabled_tools))
        if disabled_tools:
            disabled_tools_list.extend(parse_comma_separated(disabled_tools))
        if enabled_categories:
            enabled_category_list.extend(parse_comma_separated(enabled_categories))
        if disabled_categories:
            disabled_category_list.extend(parse_comma_separated(disabled_categories))
        if enabled_tools_regex:
            enabled_tools_regex_list.extend(parse_comma_separated(enabled_tools_regex))
        if disabled_tools_regex:
            disabled_tools_regex_list.extend(parse_comma_separated(disabled_tools_regex))

        # Apply read/write filters first
        apply_read_write_filters(TOOL_REGISTRY, allow_read, allow_write)
        
        # Process tools from categories and regex patterns
        enabled_tools_from_categories = process_categories(enabled_category_list, category_to_tools)
        disabled_tools_from_categories = process_categories(disabled_category_list, category_to_tools)
        
        # Get current tool names after read/write filtering
        current_tool_names = list(TOOL_REGISTRY.keys())
        enabled_tools_from_regex = process_regex_patterns(enabled_tools_regex_list, current_tool_names)
        disabled_tools_from_regex = process_regex_patterns(disabled_tools_regex_list, current_tool_names)

        # Apply enabled tools filter
        if enabled_tools_list or enabled_tools_from_categories or enabled_tools_from_regex:
            # Validate and collect all enabled tools
            all_enabled_tools = set()
            all_enabled_tools.update(validate_tools(enabled_tools_list, tool_registry_lower, "enabled_tools"))
            all_enabled_tools.update(validate_tools(enabled_tools_from_categories, tool_registry_lower, "enabled_categories"))
            all_enabled_tools.update(validate_tools(enabled_tools_from_regex, tool_registry_lower, "enabled_tools_regex"))
            
            # Remove tools not in the enabled list
            for tool_name in list(TOOL_REGISTRY.keys()):
                if tool_name.lower() not in all_enabled_tools:
                    TOOL_REGISTRY.pop(tool_name, None)

        # Apply disabled tools filter
        if disabled_tools_list or disabled_tools_from_categories or disabled_tools_from_regex:
            # Validate and collect all disabled tools
            all_disabled_tools = set()
            all_disabled_tools.update(validate_tools(disabled_tools_list, tool_registry_lower, "disabled_tools"))
            all_disabled_tools.update(validate_tools(disabled_tools_from_categories, tool_registry_lower, "disabled_categories"))
            all_disabled_tools.update(validate_tools(disabled_tools_from_regex, tool_registry_lower, "disabled_tools_regex"))

            # Remove tools in the disabled list
            for tool_name in list(TOOL_REGISTRY.keys()):
                if tool_name.lower() in all_disabled_tools:
                    TOOL_REGISTRY.pop(tool_name, None)

        # Log results
        source = filter_path if filter_path else "environment variables"
        logging.info(f"Applied tool filter from {source}")
        logging.info(f"Available tools after filtering: {list(TOOL_REGISTRY.keys())}")

    except Exception as e:
        logging.error(f"Error processing tool filter: {str(e)}")


def get_tools(mode: str = 'single', config: str = '') -> dict:
    """Filter and return available tools based on server mode and OpenSearch version.

    In 'multi' mode, returns all tools without filtering. In 'single' mode, filters tools
    based on OpenSearch version compatibility and removes base tool arguments from schemas.

    Args:
        mode (str): Server mode - 'single' for version-filtered tools, 'multi' for all tools

    Returns:
        dict: Dictionary of enabled tools with their configurations
    """
    # In multi mode, return all tools without any filtering
    if mode == 'multi':
        return TOOL_REGISTRY

    enabled = {}

    # Get OpenSearch version for compatibility checking (only in single mode)
    version = get_opensearch_version(baseToolArgs())
    logging.info(f'Connected OpenSearch version: {version}')

    # Get environment variables for tool filtering
    env_config = {
        "enabled_tools": os.getenv("OPENSEARCH_ENABLED_TOOLS", ""),
        "disabled_tools": os.getenv("OPENSEARCH_DISABLED_TOOLS", ""),
        "tool_categories": os.getenv("OPENSEARCH_TOOL_CATEGORIES", ""),
        "enabled_categories": os.getenv("OPENSEARCH_ENABLED_CATEGORIES", ""),
        "disabled_categories": os.getenv("OPENSEARCH_DISABLED_CATEGORIES", ""),
        "enabled_tools_regex": os.getenv("OPENSEARCH_ENABLED_TOOLS_REGEX", ""),
        "disabled_tools_regex": os.getenv("OPENSEARCH_DISABLED_TOOLS_REGEX", ""),
        "allow_read": os.getenv("OPENSEARCH_SETTINGS_ALLOW_READ", "false").lower() == "true",
        "allow_write": os.getenv("OPENSEARCH_SETTINGS_ALLOW_WRITE", "false").lower() == "true"
    }

    # Check if both config and env variables are set
    if config and any(env_config.values()):
        logging.warning("Both config file and environment variables are set. Using config file.")

    # Apply tool filtering
    process_tool_filter(
        filter_path=config if config else None,
        **{k: v for k, v in env_config.items() if config is ''}
    )

    # Check if running in OpenSearch Serverless mode
    is_serverless = os.getenv('AWS_OPENSEARCH_SERVERLESS', '').lower() == 'true'

    for name, info in TOOL_REGISTRY.items():
        # Create a copy to avoid modifying the original tool info
        tool_info = info.copy()

        # Skip version compatibility check for serverless mode
        # In serverless, all tools are available regardless of version
        if not is_serverless and not is_tool_compatible(version, info):
            continue

        # Remove baseToolArgs fields from input schema for single mode
        # This simplifies the schema since base args are handled internally
        schema = tool_info['input_schema'].copy()
        if 'properties' in schema:
            base_fields = baseToolArgs.model_fields.keys()
            for field in base_fields:
                schema['properties'].pop(field, None)
        tool_info['input_schema'] = schema

        enabled[name] = tool_info

    return enabled
