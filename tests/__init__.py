"""Test package.

This file exists for a specific reason. Without it, pytest imports test
modules under their bare name (``test_breakglass``) while anything using a
dotted path imports them again as ``tests.test_breakglass``. Two module objects
result, with separate module-level state, and a test that registers a callback
by dotted path then asserts on a module-level list silently observes the wrong
one.
"""
