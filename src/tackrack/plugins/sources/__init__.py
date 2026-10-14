"""Explicitly selected built-in source plugins; no third-party auto-discovery."""

from tackrack.plugins.sources.github import GitHubSource

__all__ = ["GitHubSource"]
