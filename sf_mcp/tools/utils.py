"""Shared utility functions for tool modules."""


def display_name(entry: dict) -> str:
    """Extract display name from a user record, falling back to first+last."""
    return entry.get("displayName") or f"{entry.get('firstName', '')} {entry.get('lastName', '')}".strip()
