"""Codex scanner backend.

This backend currently uses the shared scanner implementation for API-backed models.
"""

from backend.agents.solver import Scanner as CodexScanner

CodexSolver = CodexScanner
