"""通知先の共通部分。新しい通知先 (メールなど) は Notifier を継承して send() を実装し、
notify/__init__.py の build() に登録する。"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Report:
    host: str
    date: str
    items: list = field(default_factory=list)       # [(row, "new"|"remind")]  row は findings の行 (dict)
    resolved: list = field(default_factory=list)    # 今回解消した通知対象
    warnings: list = field(default_factory=list)    # 文字列
    reboot: str | None = None
    open_counts: dict = field(default_factory=dict)  # 通知条件を満たす未解消の重大度別件数
    assess: dict = field(default_factory=dict)       # key -> assessment 行
    failed: str | None = None                       # ジョブ自体の失敗

    def empty(self) -> bool:
        return not (self.items or self.resolved or self.warnings or self.reboot or self.failed)


class Notifier:
    name = "base"

    def __init__(self, cfg: dict, policy: dict):
        self.cfg = cfg
        self.policy = policy

    def render(self, report: Report) -> dict:  # pragma: no cover
        raise NotImplementedError

    def send(self, report: Report, dry_run: bool = False) -> None:  # pragma: no cover
        raise NotImplementedError
