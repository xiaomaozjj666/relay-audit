"""可疑模型名规则集 — 包内置默认 + 本地缓存 + 在线刷新。

规则数据与代码分离：各家族"不存在的版本"阈值随厂商发布节奏变化，
把规则放到 JSON 里，经 ``relay-audit --refresh-sus`` 拉取最新规则并缓存本地，
无需升级工具本身。装配顺序（见 init）：本地缓存 → 包内置 JSON → 代码内兜底。
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

MAX_PATTERNS = 64

_DEFAULT_URL = (
    # 注意分支名是 master（仓库默认分支），不是 main
    "https://raw.githubusercontent.com/xiaomaozjj666/relay-audit/master/"
    "relay_audit/data/sus_patterns.json"
)


def _data_dir() -> Path:
    """规则缓存目录：优先 RELAY_AUDIT_DATA_DIR，其次用户数据目录。"""
    env = os.environ.get("RELAY_AUDIT_DATA_DIR", "").strip()
    if env:
        return Path(env).expanduser().resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "relay-audit"
    return Path.home() / ".relay_audit"


def cache_path() -> Path:
    return _data_dir() / "sus_patterns.json"


def bundled_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "sus_patterns.json"


def default_url() -> str:
    env = os.environ.get("RELAY_AUDIT_SUS_URL", "").strip()
    return env or _DEFAULT_URL


def load_from_text(text: str) -> tuple[list[tuple[re.Pattern[str], str]], str]:
    """解析并校验规则 JSON，返回 ([(编译后正则, 标签), ...], 版本号)。"""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"规则 JSON 解析失败: {e}") from e
    if not isinstance(data, dict):
        raise ValueError("规则顶层必须是 JSON 对象")
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ValueError("规则缺少 version 字符串")
    raw = data.get("patterns")
    if not isinstance(raw, list) or not raw:
        raise ValueError("规则 patterns 必须是非空数组")
    if len(raw) > MAX_PATTERNS:
        raise ValueError(f"规则条目过多 (>{MAX_PATTERNS})")
    entries: list[tuple[re.Pattern[str], str]] = []
    for i, item in enumerate(raw):
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("pattern"), str)
            or not isinstance(item.get("label"), str)
        ):
            raise ValueError(f"第 {i + 1} 条规则缺少 pattern/label 字符串")
        try:
            compiled = re.compile(item["pattern"], re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"第 {i + 1} 条规则正则无效: {e}") from e
        entries.append((compiled, item["label"]))
    return entries, version.strip()


def load_bundled() -> tuple[list[tuple[re.Pattern[str], str]], str]:
    return load_from_text(bundled_path().read_text(encoding="utf-8"))


def load_cached() -> tuple[list[tuple[re.Pattern[str], str]], str] | None:
    path = cache_path()
    if not path.is_file():
        return None
    return load_from_text(path.read_text(encoding="utf-8"))


def install(text: str) -> str:
    """校验规则文本 → 原子写入缓存 → 立即生效。返回规则版本号。"""
    from relay_audit import patterns

    entries, version = load_from_text(text)
    cache_path().parent.mkdir(parents=True, exist_ok=True)
    tmp = cache_path().with_suffix(".tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, cache_path())
    patterns._set_sus(entries, version)
    return version


def _fetch(url: str, timeout: float) -> str:
    import httpx

    resp = httpx.get(url, timeout=timeout, follow_redirects=True)
    resp.raise_for_status()
    return resp.text


def refresh(url: str | None = None, timeout: float = 15.0) -> str:
    """拉取最新规则集并启用。返回新版本号；失败时抛异常且不改动现有规则。"""
    return install(_fetch(url or default_url(), timeout))


def init() -> None:
    """导入时装配规则：本地缓存 → 包内置 JSON → 代码内兜底。"""
    from relay_audit import patterns

    try:
        cached = load_cached()
    except Exception:
        cached = None
    if cached is not None:
        patterns._set_sus(*cached)
        return
    try:
        patterns._set_sus(*load_bundled())
    except Exception:
        patterns._use_builtin()
