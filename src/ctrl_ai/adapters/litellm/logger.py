"""LiteLLM adapter: the logging callback that writes the usage row.

Registered in the gateway config as
``callbacks: ["ctrl_ai.adapters.litellm.logger.ctrl_ai_logger"]`` (the
instance, not the class).

The row is built from ``kwargs["standard_logging_object"]`` only. That object
holds no credentials; the rest of ``kwargs`` does.
"""

from __future__ import annotations

import sys

from litellm.integrations.custom_logger import CustomLogger

from ctrl_ai.pipeline import hooks
from ctrl_ai.pipeline.runtime import get_engine


class CtrlAiLogger(CustomLogger):
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        await self._write(kwargs)

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        await self._write(kwargs)

    async def _write(self, kwargs: dict) -> None:
        try:
            slo = kwargs.get("standard_logging_object")
            if not slo:
                return
            await hooks.after_call(get_engine(), slo)
        except Exception as exc:
            # A logging bug must never break the request path.
            print(f"ctrl-ai: usage row failed ({type(exc).__name__})", file=sys.stderr)


ctrl_ai_logger = CtrlAiLogger()
