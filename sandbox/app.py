"""Compatibility module for the package-owned demo sandbox."""

from sentinel.sandbox.app import CANARY_SECRET, ChatBody, app, guarded_demo, health, vulnerable_chat

__all__ = ["CANARY_SECRET", "ChatBody", "app", "guarded_demo", "health", "vulnerable_chat"]
