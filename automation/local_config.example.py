"""
Local automation config template.
Copy this to local_config.py and fill in your values.
"""

# Required: OpenAI-compatible API
OPENAI_API_KEY = "sk-..."
OPENAI_BASE_URL = "https://api.openai.com/v1"  # or DashScope, OpenRouter, etc.

# Model configuration
AUTOMATION_MODEL = "gpt-4o"
AUTOMATION_MODEL_PLANNER = "gpt-4o"
AUTOMATION_MODEL_EXECUTOR = "gpt-4o"
AUTOMATION_MODEL_DECIDER = "gpt-4o"

# Python binary for running exploits
AUTOMATION_PYTHON = "python3"

# OpenHands agent model (optional)
OPENHANDS_MODEL = "gpt-4o"
