from .base import Rule

# Day 2+ rules get registered here.
ALL_RULES: list[type[Rule]] = []

__all__ = ["Rule", "ALL_RULES"]