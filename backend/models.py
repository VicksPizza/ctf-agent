"""Model resolution — Bedrock, Azure OpenAI, Zen, Google AI Studio."""

from __future__ import annotations

from typing import TYPE_CHECKING

import boto3
from pydantic_ai.models import Model
from pydantic_ai.models.bedrock import BedrockConverseModel, BedrockModelSettings
from pydantic_ai.models.google import GoogleModel, GoogleModelSettings
from pydantic_ai.models.openai import OpenAIModel, OpenAIModelSettings
from pydantic_ai.providers.bedrock import BedrockProvider
from pydantic_ai.providers.google import GoogleProvider
from pydantic_ai.providers.openai import OpenAIProvider
from pydantic_ai.settings import ModelSettings

if TYPE_CHECKING:
    from backend.config import Settings

# Default model specs — claude-sdk and codex providers use the new solver backends
DEFAULT_MODELS: list[str] = [
    "claude-sdk/claude-opus-4-6/medium",
    "claude-sdk/claude-opus-4-6/max",
    "codex/gpt-5.4",
    "codex/gpt-5.4-mini",
    "codex/gpt-5.3-codex",
]

# Context window sizes (tokens)
CONTEXT_WINDOWS: dict[str, int] = {
    "us.anthropic.claude-opus-4-6-v1": 1_000_000,
    "claude-opus-4-6": 1_000_000,
    "gpt-5.4": 1_000_000,
    "gpt-5.4-mini": 400_000,
    "gpt-5.3-codex": 1_000_000,
    "gpt-5.3-codex-spark": 128_000,
    "gemini-3-flash-preview": 1_000_000,
}

# Models that support vision
VISION_MODELS: set[str] = {
    "us.anthropic.claude-opus-4-6-v1",
    "claude-opus-4-6",
    "gpt-5.4",
    "gpt-5.4-mini",
    "gemini-3-flash-preview",
}

# Vulnerability research swarm configurations
# Each swarm specializes in a vulnerability class with custom prompts and model selections
SWARM_CONFIGS: dict[str, dict] = {
    "xss": {
        "models": ["claude-opus-4-6", "gpt-5.4"],
        "system_prompt_extra": (
            "You are a web security specialist focused on XSS (Cross-Site Scripting) vulnerabilities. "
            "Analyze the target for reflected, stored, and DOM-based XSS. "
            "Look for unsanitized user input rendered in HTML/JS context. "
            "Your proof-of-concept must trigger alert(1), exfiltrate a cookie, or demonstrate "
            "arbitrary JavaScript execution. Test both input validation and output encoding."
        ),
    },
    "sqli": {
        "models": ["claude-opus-4-6", "gpt-5.4"],
        "system_prompt_extra": (
            "You are a database security specialist focused on SQL injection. "
            "Try UNION-based, error-based, blind boolean-based, and time-based techniques. "
            "Analyze SQL queries, ORM configurations, and parameterization. "
            "Your proof-of-concept must successfully dump at least one row of sensitive data "
            "or modify database state. Use sqlmap and manual payload crafting."
        ),
    },
    "bof": {
        "models": ["claude-opus-4-6", "gpt-5.4"],
        "system_prompt_extra": (
            "You are a binary security specialist focused on buffer overflow vulnerabilities. "
            "Analyze stack and heap layouts. Use pwntools, GDB, and ASAN. "
            "Your proof-of-concept must achieve instruction pointer (EIP/RIP) control, "
            "execute arbitrary code, or crash with a distinguishable pattern. "
            "Use fuzzing, static analysis, and dynamic debugging."
        ),
    },
    "uaf": {
        "models": ["claude-opus-4-6"],
        "system_prompt_extra": (
            "You are a memory safety specialist focused on use-after-free vulnerabilities. "
            "Analyze object lifetime, memory deallocation patterns, and reference counting. "
            "Use Valgrind, AddressSanitizer, and GDB. "
            "Your proof-of-concept must demonstrate dangling pointer access, heap corruption, "
            "or arbitrary memory read/write through use-after-free."
        ),
    },
    "auth": {
        "models": ["claude-opus-4-6", "gpt-5.4"],
        "system_prompt_extra": (
            "You are an authentication and authorization specialist. "
            "Focus on authentication bypass, insecure direct object reference (IDOR), "
            "broken access control, JWT weaknesses, and session management flaws. "
            "Your proof-of-concept must access a resource belonging to another user, "
            "elevate privileges, or bypass authentication entirely. "
            "Test token manipulation, session fixation, and permission checks."
        ),
    },
    "source": {
        "models": ["claude-opus-4-6"],
        "system_prompt_extra": (
            "You are a source code security analyst performing static and dynamic analysis. "
            "Run semgrep with vulnerability rules, bandit for Python, and other static tools. "
            "Identify dangerous code patterns: hardcoded secrets, unsafe deserialization, "
            "command injection, path traversal, insecure randomness, and XXE. "
            "Then attempt dynamic confirmation of each finding via targeted tests."
        ),
    },
}


def resolve_model(spec: str, settings: Settings) -> Model:
    """Resolve a 'provider/model_id' spec to a Pydantic AI Model."""
    provider = provider_from_spec(spec)
    model_id = model_id_from_spec(spec)
    match provider:
        case "bedrock":
            if settings.aws_bearer_token:
                return BedrockConverseModel(
                    model_id,
                    provider=BedrockProvider(
                        api_key=settings.aws_bearer_token,
                        region_name=settings.aws_region,
                    ),
                )
            else:
                session = boto3.Session()
                client = session.client("bedrock-runtime", region_name=settings.aws_region)
                return BedrockConverseModel(
                    model_id,
                    provider=BedrockProvider(bedrock_client=client),
                )
        case "azure":
            return OpenAIModel(
                model_id,
                provider=OpenAIProvider(
                    base_url=settings.azure_openai_endpoint,
                    api_key=settings.azure_openai_api_key,
                ),
            )
        case "zen":
            return OpenAIModel(
                model_id,
                provider=OpenAIProvider(
                    base_url="https://opencode.ai/zen/v1",
                    api_key=settings.opencode_zen_api_key,
                ),
            )
        case "google":
            return GoogleModel(
                model_id,
                provider=GoogleProvider(api_key=settings.gemini_api_key),
            )
        case "claude-sdk" | "codex":
            raise ValueError(
                f"Provider '{provider}' uses its own solver backend, not Pydantic AI. "
                f"resolve_model() should not be called for {spec}."
            )
        case _:
            raise ValueError(f"Unknown provider: {provider}")


def resolve_model_settings(spec: str) -> ModelSettings:
    """Get provider-specific model settings with caching enabled."""
    provider = spec.split("/", 1)[0]
    match provider:
        case "bedrock":
            return BedrockModelSettings(
                max_tokens=128_000,
                bedrock_cache_instructions=True,
                bedrock_cache_tool_definitions=True,
                bedrock_cache_messages=True,
            )
        case "azure" | "zen":
            # Azure/Zen use OpenAI chat completions — server-side prompt caching
            # is automatic, no explicit config needed. Set max_tokens to avoid
            # reserving the full context window.
            return OpenAIModelSettings(
                max_tokens=128_000,
            )
        case "google":
            return GoogleModelSettings(
                max_tokens=64_000,
                google_thinking_config={
                    "thinking_level": "high",
                    "include_thoughts": True,
                },
            )
        case _:
            return ModelSettings(max_tokens=128_000)


def model_id_from_spec(spec: str) -> str:
    """Extract just the model ID from a spec (strips effort suffix)."""
    parts = spec.split("/")
    return parts[1] if len(parts) >= 2 else spec


def provider_from_spec(spec: str) -> str:
    """Extract the provider from a spec."""
    return spec.split("/", 1)[0]


def effort_from_spec(spec: str) -> str | None:
    """Extract effort level from a spec like 'claude-sdk/claude-opus-4-6/max'."""
    parts = spec.split("/")
    if len(parts) >= 3 and parts[2] in ("low", "medium", "high", "max"):
        return parts[2]
    return None


def supports_vision(spec: str) -> bool:
    """Check if a model spec supports vision."""
    return model_id_from_spec(spec) in VISION_MODELS


def context_window(spec: str) -> int:
    """Get context window size for a model spec."""
    return CONTEXT_WINDOWS.get(model_id_from_spec(spec), 200_000)
