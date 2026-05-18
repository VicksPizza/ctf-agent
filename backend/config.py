"""Pydantic Settings — credentials from .env file + environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # API Keys
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""

    # Provider-specific (optional, for Bedrock/Azure/Zen fallback)
    aws_region: str = "us-east-1"
    aws_bearer_token: str = ""
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    opencode_zen_api_key: str = ""

    # Vulnerability research
    targets_file: str = "targets.yml"  # Path to targets YAML file
    max_concurrent_swarms: int = 10  # Max parallel scanner swarms
    max_iterations_per_swarm: int = 1  # Max attempts before giving up
    container_memory_limit: str = "16g"

    # Infra
    sandbox_image: str = "vuln-research-sandbox"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}
