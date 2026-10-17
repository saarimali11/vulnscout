# This file makes rules/ a package and keeps the master list of rules.

from .base import Rule
from .eval_exec import EvalExecRule
from .shell_injection import ShellInjectionRule

# Every rule we write gets added to this list.
ALL_RULES: list[type[Rule]] = [
    EvalExecRule,
    ShellInjectionRule,
]

__all__ = ["Rule", "ALL_RULES", "EvalExecRule", "ShellInjectionRule"]