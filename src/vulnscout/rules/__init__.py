# This file makes rules/ a package and keeps the master list of rules.

from .base import Rule

# Every rule we write gets added to this list.
# scanner.py loops over it, so a new rule just needs to be registered here.
# It's empty on Day 1 because we haven't written any rules yet.
ALL_RULES: list[type[Rule]] = []

# __all__ controls what "from vulnscout.rules import *" exposes
__all__ = ["Rule", "ALL_RULES"]