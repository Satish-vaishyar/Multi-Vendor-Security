"""Orbit cloud-assessment module (scanner side).

Self-contained and additive: nothing here imports from, or is imported by, the existing audit pipeline until the
backend explicitly opts in behind the CLOUD_MODULE_ENABLED flag. See docs/CLOUD_MODULE_RTM.md.
"""

__version__ = "0.1.0"
