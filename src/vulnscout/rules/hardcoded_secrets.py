# VS004: flags secrets hardcoded in source code.
# Anyone who can read the code (including everyone who ever clones the repo,
# since git keeps history forever) can read the secret.
# OWASP: A07 Identification and Authentication Failures.
#
# Three ways something gets flagged:
#1. NAME:password = "hunter2" (suspicious name + real-looking value)
#2. PATTERN: x = "AKIA..." (value looks like a known credential)
#3. ENTROPY: blob = "Zk3vQ9xT7p..." (long and random-looking)
#
# Known limits:
# "token_type = 'bearer'" gets flagged (name says token, value is a string).
# Inline suppression comes on Day 9 to handle cases like this.
# it only looks at plain string values, not ones built at runtime.

import ast
import math
import re
from collections import Counter

from ..models import Severity
from .base import Rule

# Single words that make a variable name suspicious.
# We match whole words (not substrings) so "tokenizer" is NOT flagged
# but "auth_token" is.
SECRET_WORDS = {"password", "passwd", "pwd", "passphrase", "secret", "token",
                "apikey", "credentials"}

# Two-word combos, e.g. api_key. We check pairs of neighbouring words.
SECRET_PAIRS = {("api", "key"), ("secret", "key"), ("private", "key"),
                ("access", "key"), ("auth", "key")}

# Values that are obviously fake/placeholder, so flagging them is just noise
PLACEHOLDER_VALUES = {"changeme", "change_me", "password", "secret", "token",
                      "xxx", "todo", "none", "null", "example", "test",
                      "dummy", "placeholder"}

# Regexes for strings that look like real credentials.
# (label, pattern)
KNOWN_PATTERNS = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("API secret key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# Entropy settings. Hex strings (like sha256 hashes) max out at 4.0 bits per
# character, so a 4.5 cutoff skips them but still catches base64-style tokens.
MIN_ENTROPY_LENGTH = 24
ENTROPY_THRESHOLD = 4.5


def shannon_entropy(text: str) -> float:
    """Bits of randomness per character. 'aaaa' = 0, truly random = high."""
    if not text:
        return 0.0
    counts = Counter(text) # how many times each character appears
    total = len(text)
    # Shannon's formula: -sum(p * log2(p)) over each character's probability p
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def name_words(name: str) -> list[str]:
    """Split a name into lowercase words: apiKey / API_KEY / api-key -> [api, key]."""
    name = name.replace("-", "_")
    # Put an underscore between a lowercase letter and an uppercase one (camelCase)
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()
    return [w for w in spaced.split("_") if w]


def is_secret_name(name: str) -> bool:
    words = name_words(name)
    if any(w in SECRET_WORDS for w in words):
        return True
    # zip(words, words[1:]) gives every pair of neighbouring words
    return any(pair in SECRET_PAIRS for pair in zip(words, words[1:]))


def looks_like_placeholder(value: str) -> bool:
    v = value.strip()
    if not v:
        return True # empty string
    low = v.lower()
    if low in PLACEHOLDER_VALUES:
        return True
    if v.startswith(("<", "${", "{{", "%(")): # <your-key>, ${ENV_VAR}, {{ template }}
        return True
    if low.startswith("your"): # your_password_here
        return True
    return set(low) <= set("x*.-_") # xxxxxxxx, ********


def looks_high_entropy(value: str) -> bool:
    if len(value) < MIN_ENTROPY_LENGTH:
        return False
    # Real sentences have spaces; URLs and file paths aren't secrets
    if any(c.isspace() for c in value) or "://" in value or value.startswith("/"):
        return False
    return shannon_entropy(value) >= ENTROPY_THRESHOLD


class HardcodedSecretsRule(Rule):
    id = "VS004"
    owasp = "A07:2021-Identification and Authentication Failures"
    severity = Severity.HIGH

    def __init__(self, path: str):
        super().__init__(path)
        # ids of string nodes we've already reported, so one secret never
        # produces two findings (e.g. name match AND pattern match)
        self._seen: set[int] = set()

    # ---- core check ----

    def _check(self, name: str, value_node: ast.AST, report_node: ast.AST) -> None:
        """Check one 'name = value' pair."""
        # Only plain string values can be hardcoded secrets
        if not (isinstance(value_node, ast.Constant) and isinstance(value_node.value, str)):
            return
        value = value_node.value

        if is_secret_name(name):
            # Suspicious name: flag unless the value is obviously a placeholder
            if not looks_like_placeholder(value):
                self._seen.add(id(value_node))
                self.report(report_node,
                            f"hardcoded secret in '{name}'; load it from an "
                            "environment variable or a secrets manager instead")
        elif looks_high_entropy(value):
            # Innocent name, but the value looks like a random token
            self._seen.add(id(value_node))
            self.report(report_node,
                        f"'{name}' holds a high-entropy string "
                        f"({shannon_entropy(value):.1f} bits/char) that looks like a secret")

    @staticmethod
    def _target_name(target: ast.AST) -> str | None:
        """Get a usable name from an assignment target, or None if we can't."""
        if isinstance(target, ast.Name): # password = ...
            return target.id
        if isinstance(target, ast.Attribute): # self.password = ...
            return target.attr
        if (isinstance(target, ast.Subscript) # config["password"] = ...
                and isinstance(target.slice, ast.Constant)
                and isinstance(target.slice.value, str)):
            return target.slice.value
        return None

    # visitors: each one feeds name/value pairs into _check  

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            name = self._target_name(target)
            if name:
                self._check(name, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # password: str = "hunter2" (value is None for a bare annotation)
        name = self._target_name(node.target)
        if name and node.value is not None:
            self._check(name, node.value, node)
        self.generic_visit(node)

    def visit_Dict(self, node: ast.Dict) -> None:
        # {"password": "hunter2"}. keys can be None when using {**other}
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                self._check(key.value, value, value)
        self.generic_visit(node)

    def visit_keyword(self, node: ast.keyword) -> None:
        # connect(password="hunter2"). node.arg is None for **kwargs
        if node.arg:
            self._check(node.arg, node.value, node.value)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        # Pattern check: runs on EVERY string, whatever it's assigned to.
        # Skipped if the name/entropy check already reported this string.
        if isinstance(node.value, str) and id(node) not in self._seen:
            for label, pattern in KNOWN_PATTERNS:
                if pattern.search(node.value):
                    self.report(node, f"string looks like a {label}; "
                                      "never commit credentials to source control")
                    break # one finding per string is enough