from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

from .models import CanonicalMethod, MethodFingerprint

_API_PATTERN = re.compile(r"L(?:java|javax|android)/[^;]+;->[^(, }]+")
_STRING_PATTERN = re.compile(r"\"([^\"]*)\"")


def _opcode_family(name: str) -> str:
    base = name.lower().split("/")[0]
    for prefix, family in (
        ("invoke", "invoke"),
        ("const", "const"),
        ("move", "move"),
        ("if-", "if"),
        ("goto", "goto"),
        ("return", "return"),
        ("iget", "field-get"),
        ("sget", "field-get"),
        ("iput", "field-put"),
        ("sput", "field-put"),
        ("aget", "array-get"),
        ("aput", "array-put"),
        ("new-", "new"),
        ("packed-switch", "switch"),
        ("sparse-switch", "switch"),
    ):
        if base.startswith(prefix):
            return family
    return base.split("-")[0]


def canonicalize_instructions(
    instructions: Iterable[tuple[str, str]],
) -> CanonicalMethod:
    tokens: list[str] = []
    api_calls: list[str] = []
    constants: list[str] = []
    block_signature: list[str] = []
    for name, output in instructions:
        family = _opcode_family(name)
        tokens.append(family)
        if family in {"if", "goto", "switch", "return", "throw"}:
            block_signature.append(family)
        if family == "invoke":
            match = _API_PATTERN.search(output)
            if match:
                api_calls.append(match.group(0))
        for value in _STRING_PATTERN.findall(output):
            category = "empty" if not value else f"string:{min(len(value) // 8, 8)}"
            constants.append(category)
    digest_input = "\x1f".join(
        tokens + ["|api-calls|"] + api_calls + ["|constant-categories|"] + constants
    )
    canonical_hash = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()
    return CanonicalMethod(
        tuple(tokens),
        tuple(api_calls),
        tuple(constants),
        tuple(block_signature),
        canonical_hash,
    )


def build_method_fingerprint(
    dex_path: str,
    class_name: str,
    method_name: str,
    descriptor: str,
    instructions: Iterable[tuple[str, str]],
    *,
    third_party_prefixes: tuple[str, ...] = (),
    business_prefixes: tuple[str, ...] = (),
) -> MethodFingerprint:
    instruction_list = list(instructions)
    canonical = canonicalize_instructions(instruction_list)
    if business_prefixes and class_name.startswith(business_prefixes):
        third_party = False
    else:
        third_party = class_name.startswith(third_party_prefixes)
    module = dex_path.split("/", 1)[0] if "/" in dex_path else "base"
    identifier = f"{class_name}->{method_name}{descriptor}"
    return MethodFingerprint(
        identifier=identifier,
        module=module,
        dex_path=dex_path,
        class_name=class_name,
        method_name=method_name,
        descriptor=descriptor,
        instruction_count=len(instruction_list),
        canonical_hash=canonical.canonical_hash,
        opcode_tokens=list(canonical.tokens),
        api_calls=list(canonical.api_calls),
        constants=list(canonical.constants),
        block_signature=list(canonical.block_signature),
        third_party=third_party,
    )


def should_retain_method(
    method: MethodFingerprint,
    *,
    minimum_instructions: int,
    include_third_party: bool = False,
) -> bool:
    if method.instruction_count < minimum_instructions:
        return False
    return include_third_party or not method.third_party


def extract_methods_from_dex(
    data: bytes,
    dex_path: str,
    *,
    third_party_prefixes: tuple[str, ...],
    business_prefixes: tuple[str, ...],
    minimum_instructions: int = 1,
    include_third_party: bool = True,
) -> list[MethodFingerprint]:
    from loguru import logger

    logger.disable("androguard")
    from androguard.core.dex import DEX  # type: ignore[import-untyped]

    vm = DEX(data)
    methods: list[MethodFingerprint] = []
    for class_item in vm.get_classes():
        for method in class_item.get_methods():
            instructions = [
                (instruction.get_name(), instruction.get_output())
                for instruction in method.get_instructions()
            ]
            if not instructions:
                continue
            fingerprint = build_method_fingerprint(
                dex_path,
                method.get_class_name(),
                method.get_name(),
                method.get_descriptor(),
                instructions,
                third_party_prefixes=third_party_prefixes,
                business_prefixes=business_prefixes,
            )
            if should_retain_method(
                fingerprint,
                minimum_instructions=minimum_instructions,
                include_third_party=include_third_party,
            ):
                methods.append(fingerprint)
    return methods
