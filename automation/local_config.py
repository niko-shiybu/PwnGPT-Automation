"""
Local automation config (code-based, no per-shell export needed).

Fill these values for your machine.
Keep this file local/private if it contains secrets.
"""

# Example:
# OPENAI_API_KEY = "sk-..."
# OPENAI_BASE_URL = "https://openrouter.ai/api/v1"
# AUTOMATION_MODEL = "openai/gpt-4o-2024-11-20"
# AUTOMATION_MODEL_PLANNER = "openai/gpt-4o-2024-11-20"
# AUTOMATION_MODEL_EXECUTOR = "openai/gpt-4o-mini"
# AUTOMATION_MODEL_DECIDER = "openai/gpt-4o-mini"
# AUTOMATION_PYTHON = "/home/fyc/miniconda3/envs/pwngpt/bin/python3"

OPENAI_API_KEY = "sk-72c332123fef4ca58917c4fda6021302"
OPENAI_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
AUTOMATION_MODEL = "qwen-max"
AUTOMATION_MODEL_PLANNER = "qwen-max"
AUTOMATION_MODEL_EXECUTOR = "qwen-max"
AUTOMATION_MODEL_DECIDER = "qwen-max"
AUTOMATION_PYTHON = "/home/fyc/miniconda3/envs/pwngpt/bin/python3"

# OpenHands agent model (set to your preferred model)
OPENHANDS_MODEL = "qwen-max"

# OpenHands SDK configuration (new)
OPENHANDS_ENABLED = True
OPENHANDS_API_KEY = OPENAI_API_KEY  # reuse existing key by default
OPENHANDS_BASE_URL = OPENAI_BASE_URL  # reuse DashScope base URL for Qwen
OPENHANDS_SANDBOX = "local"  # "local" only for now (no DockerWorkspace in SDK v1.19)
OPENHANDS_MAX_ITERATIONS = 30
