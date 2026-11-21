from __future__ import annotations

from .base import Notifier, Report
from .slack import SlackNotifier

REGISTRY = {"slack": SlackNotifier}


def build(cfg: dict) -> list[Notifier]:
    """notify.<名前>.enabled が true の通知先を作る"""
    n = cfg["notify"]
    return [cls(n[name], n["policy"]) for name, cls in REGISTRY.items()
            if isinstance(n.get(name), dict) and n[name].get("enabled")]


__all__ = ["Notifier", "Report", "build"]
