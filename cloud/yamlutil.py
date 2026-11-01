"""Safe YAML loading with source-line provenance (shared by the CloudFormation, Kubernetes, ROS and Heat parsers).

* Uses SafeLoader only: no arbitrary object construction.
* Unknown tags (CloudFormation !Ref / !Sub / !GetAtt ...) are kept as {"Fn::<Tag>": value} instead of failing.
* Mappings and sequences remember the 1-based line they start on, and each mapping key remembers its own line.
* Resource caps: the EXPANDED node count (aliases counted every time they are used, so "billion laughs" documents are
  refused before anything is built) and the nesting depth are bounded; recursive aliases are refused.
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


MAX_YAML_NODES = 500_000       # expanded nodes across all documents of one file
MAX_YAML_DEPTH = 100


def _expanded_size(node: yaml.Node, memo: dict, depth: int = 0) -> int:
    """Number of nodes the document would expand to once aliases are resolved (memoised, so cheap to compute)."""
    if depth > MAX_YAML_DEPTH:
        raise YamlError("YAML is nested too deeply (or contains a recursive alias)")
    key = id(node)
    if key in memo:
        return memo[key]
    if isinstance(node, yaml.ScalarNode):
        size = 1
    elif isinstance(node, yaml.SequenceNode):
        size = 1 + sum(_expanded_size(c, memo, depth + 1) for c in node.value)
    else:
        size = 1 + sum(_expanded_size(k, memo, depth + 1) + _expanded_size(v, memo, depth + 1) for k, v in node.value)
    if size > MAX_YAML_NODES:
        raise YamlError("YAML expands to too many nodes (alias expansion)")
    memo[key] = size
    return size


def load_all(text: str) -> List[Any]:
    """Parse every document in `text`. Raises YamlError on malformed or abusive input (never executes anything)."""
    docs: List[Any] = []
    loader = _Loader(text)
    memo: dict = {}
    total = 0
    try:
        while loader.check_node():
            node = loader.get_node()
            total += _expanded_size(node, memo)
            if total > MAX_YAML_NODES:
                raise YamlError("YAML expands to too many nodes (alias expansion)")
            doc = loader.construct_document(node)
            if doc is not None:
                docs.append(doc)
    except yaml.YAMLError as e:
        raise YamlError(str(e).splitlines()[0] if str(e) else "invalid YAML")
    except RecursionError:
        raise YamlError("YAML is nested too deeply")
    finally:
        loader.dispose()
    return docs


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
