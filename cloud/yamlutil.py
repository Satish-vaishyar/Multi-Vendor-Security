"""Safe YAML loading with source-line provenance (shared by the CloudFormation, Kubernetes, ROS and Heat parsers).

* Uses SafeLoader only: no arbitrary object construction.
* Unknown tags (CloudFormation !Ref / !Sub / !GetAtt ...) are kept as {"Fn::<Tag>": value} instead of failing.
* Mappings and sequences remember the 1-based line they start on, and each mapping key remembers its own line.
"""
from __future__ import annotations

from typing import Any, Dict, List

import yaml


class LDict(dict):
    """dict that remembers where it and its keys appeared in the source."""
    line: int = 0
    key_lines: Dict[Any, int]

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.key_lines = {}


class LList(list):
    line: int = 0


class _Loader(yaml.SafeLoader):
    pass


def _mapping(loader: _Loader, node: yaml.MappingNode) -> LDict:
    out = LDict()
    out.line = node.start_mark.line + 1
    for knode, vnode in node.value:
        key = loader.construct_object(knode, deep=True)
        out[key] = loader.construct_object(vnode, deep=True)
        out.key_lines[key] = knode.start_mark.line + 1
    return out


def _sequence(loader: _Loader, node: yaml.SequenceNode) -> LList:
    out = LList(loader.construct_object(n, deep=True) for n in node.value)
    out.line = node.start_mark.line + 1
    return out


def _tagged(loader: _Loader, suffix: str, node: yaml.Node) -> LDict:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = _sequence(loader, node)
    else:
        value = _mapping(loader, node)
    out = LDict({(suffix if suffix in ("Ref", "Condition") else "Fn::" + suffix): value})
    out.line = node.start_mark.line + 1
    return out


_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)
_Loader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _sequence)
_Loader.add_multi_constructor("!", _tagged)


class YamlError(ValueError):
    pass


def load_all(text: str) -> List[Any]:
    """Parse every document in `text`. Raises YamlError on malformed input (never executes anything)."""
    try:
        return [d for d in yaml.load_all(text, Loader=_Loader) if d is not None]
    except yaml.YAMLError as e:
        raise YamlError(str(e).splitlines()[0] if str(e) else "invalid YAML")


def load(text: str) -> Any:
    docs = load_all(text)
    return docs[0] if docs else None


def line_of(node: Any, key: Any = None, default: int = 1) -> int:
    """Best-effort 1-based line for a parsed node (or one of its keys)."""
    if isinstance(node, LDict):
        if key is not None and key in node.key_lines:
            return node.key_lines[key]
        return node.line or default
    if isinstance(node, LList):
        return node.line or default
    return default
