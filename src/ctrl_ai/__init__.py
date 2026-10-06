"""ctrl-ai: the guardrail code that runs inside the LiteLLM gateway.

Only ``litellm_guardrail`` and ``litellm_logger`` import LiteLLM; every other
module is plain Python so it can be tested on the host.
"""
