# Copyright OpenSearch Contributors
# SPDX-License-Identifier: Apache-2.0

import re
import logging
import yaml
from semver import Version


def is_tool_compatible(current_version: Version, tool_info: dict = {}):
    """Check if a tool is compatible with the current OpenSearch version.

    Args:
        current_version (Version): The current OpenSearch version
        tool_info (dict): Tool information containing min_version and max_version

    Returns:
        bool: True if the tool is compatible, False otherwise
    """
    min_tool_version = Version.parse(
        tool_info.get('min_version', '0.0.0'), optional_minor_and_patch=True
    )
    max_tool_version = Version.parse(
        tool_info.get('max_version', '99.99.99'), optional_minor_and_patch=True
    )
    return min_tool_version <= current_version <= max_tool_version


def parse_comma_separated(text, separator=','):
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
            logging.warning(f'Invalid tool filter configuration in {filter_path}')
            return None
        return config
    except Exception as e:
        logging.error(f'Error loading filter config: {str(e)}')
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


def apply_write_filter(registry, allow_write):
    """Apply allow_write filters to the registry."""
    for tool_name in list(registry.keys()):
        http_methods = registry[tool_name].get('http_methods', [])
        if 'GET' not in http_methods:
            registry.pop(tool_name, None)
