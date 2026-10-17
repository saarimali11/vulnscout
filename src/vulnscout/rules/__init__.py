# This file makes rules/ a package and keeps the master list of rules.

from .base import Rule
from .eval_exec import EvalExecRule

# Every rule we write gets added to this list.
# scanner.py loops over it, so a new rule only needs to be registered here.
ALL_RULES: list[type[Rule]] = [
    EvalExecRule,
]

# __all__ controls what "from vulnscout.rules import *" exposes
__all__ = ["Rule", "ALL_RULES", "EvalExecRule"]