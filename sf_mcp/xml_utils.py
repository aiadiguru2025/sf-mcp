"""Safe XML parsing and SAP date utilities."""

import re
from datetime import datetime, date, timezone

import defusedxml.ElementTree as DefusedET


def xml_to_dict(xml_content: bytes) -> dict:
    """
    Safely parse XML to dictionary using defusedxml to prevent XXE attacks.

    Args:
        xml_content: XML content as bytes

    Returns:
        Dictionary representation of the XML
    """
    def element_to_dict(element):
        """Recursively convert an XML element to a dictionary."""
        result = {}

        if element.attrib:
            for key, value in element.attrib.items():
                result[f"@{key}"] = value

        children = list(element)
        if children:
            child_dict = {}
            for child in children:
                child_data = element_to_dict(child)
                tag = child.tag
                if '}' in tag:
                    tag = tag.split('}')[1]

                if tag in child_dict:
                    if not isinstance(child_dict[tag], list):
                        child_dict[tag] = [child_dict[tag]]
                    child_dict[tag].append(child_data if child_data else child.text)
                else:
                    child_dict[tag] = child_data if child_data else child.text
            result.update(child_dict)
        elif element.text and element.text.strip():
            if result:
                result['#text'] = element.text.strip()
            else:
                return element.text.strip()

        return result if result else None

    root = DefusedET.fromstring(xml_content)

    root_tag = root.tag
    if '}' in root_tag:
        root_tag = root_tag.split('}')[1]

    return {root_tag: element_to_dict(root)}


def parse_sap_date(date_str: str) -> str:
    """
    Parse SAP /Date(timestamp)/ format to ISO 8601.

    Handles multiple formats:
    - SAP format: /Date(1234567890000)/
    - ISO format: 2024-01-15T00:00:00
    - Date-only format: 2024-01-15

    Args:
        date_str: Date string in any supported format

    Returns:
        ISO 8601 formatted date string, or empty string if input is empty
    """
    if not date_str:
        return ""
    date_str = str(date_str)
    match = re.search(r'/Date\((\d+)\)/', date_str)
    if match:
        timestamp_ms = int(match.group(1))
        dt = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
        return dt.isoformat()
    return date_str


def parse_hire_date(hire_date_raw: str) -> date | None:
    """
    Parse a hire date from various SAP formats into a Python date.

    Args:
        hire_date_raw: Raw date string from SAP API

    Returns:
        date object or None if parsing fails
    """
    if not hire_date_raw or not isinstance(hire_date_raw, str):
        return None
    try:
        if "/Date(" in hire_date_raw:
            ts = int(hire_date_raw.split("(")[1].split(")")[0].split("+")[0].split("-")[0])
            return date.fromtimestamp(ts / 1000)
        else:
            return datetime.strptime(hire_date_raw[:10], "%Y-%m-%d").date()
    except (ValueError, TypeError, IndexError):
        return None
