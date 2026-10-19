# This file makes rules/ a package and keeps the master list of rules.

from .base import Rule
from .eval_exec import EvalExecRule
from .shell_injection import ShellInjectionRule
from .sql_injection import SqlInjectionRule
from .hardcoded_secrets import HardcodedSecretsRule

# Every rule I write gets added to this list.
# scanner.py loops over it, so a new rule only needs to be registered here.
ALL_RULES: list[type[Rule]] = [
    EvalExecRule,
    ShellInjectionRule,
    SqlInjectionRule,
    HardcodedSecretsRule,
]

__all__ = [
    "Rule", "ALL_RULES", "EvalExecRule", "ShellInjectionRule",
    "SqlInjectionRule", "HardcodedSecretsRule",
]