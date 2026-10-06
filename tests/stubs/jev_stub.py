"""Stub of the Jev decision API for keyless tests (standard library only).

Routes:
  POST   /v1/systemone    401 without a bearer, 422 for a missing field, otherwise one answer per question
  GET    /_stub/health    200 {"ok": true}
  GET    /_stub/requests  what was received since the last reset (lengths and ids, never the text)
  DELETE /_stub/requests  reset that list

Markers in `state`: ATTACKTEST scores 0.93 instead of 0.02, JEV-500-TEST answers HTTP 500,
JEV-SLOW-TEST waits 6 seconds before answering.
JEV-UNCERTAIN-TEST scores 0.55 (the uncertain band), SLOW-1S-TEST waits one second.
"""

from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "9002"))
ATTACK_SCORE = 0.93
BENIGN_SCORE = 0.02
UNCERTAIN_SCORE = 0.55
SLOW_SECONDS = 6
REQUIRED_FIELDS = ("state", "model", "questions")

LOG: list[dict] = []
LOCK = threading.Lock()


def state_text(state) -> str:
    """The state as text, so markers are found in string and structured states alike."""
    return state if isinstance(state, str) else json.dumps(state)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _route(self) -> str:
        return self.path.split("?", 1)[0]

    def _json(self, status: int, obj) -> None:
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _record(self, body, status: int, bearer: bool) -> None:
        body = body if isinstance(body, dict) else {}
        questions = body.get("questions")
        state = body.get("state")
        entry = {
            "ts": time.time(),
            "method": self.command,
            "path": self.path,
            "header_names": sorted({k.lower() for k in self.headers}),
            "bearer_present": bearer,
            "model": body.get("model") if isinstance(body.get("model"), str) else None,
            "question_ids": sorted(questions) if isinstance(questions, dict) else [],
            "state_length": len(state)
            if isinstance(state, str)
            else (len(state_text(state)) if state is not None else 0),
            "status": status,
        }
        with LOCK:
            LOG.append(entry)
        print("STUB-JEV " + json.dumps(entry), flush=True)

    def do_GET(self):
        route = self._route()
        if route == "/_stub/health":
            return self._json(200, {"ok": True})
        if route == "/_stub/requests":
            with LOCK:
                return self._json(200, list(LOG))
        return self._json(404, {"detail": "Not Found"})

    def do_DELETE(self):
        if self._route() == "/_stub/requests":
            with LOCK:
                LOG.clear()
            return self._json(200, {"ok": True})
        return self._json(404, {"detail": "Not Found"})

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        auth = self.headers.get("authorization") or ""
        bearer = auth.lower().startswith("bearer ") and bool(auth[7:].strip())

        if self._route() != "/v1/systemone":
            self._record(body, 404, bearer)
            return self._json(404, {"detail": "Not Found"})
        if not bearer:
            self._record(body, 401, bearer)
            return self._json(401, {"detail": "Not authenticated"})
        if not isinstance(body, dict):
            self._record(body, 422, bearer)
            return self._json(
                422, {"detail": [{"loc": ["body"], "msg": "Field required", "type": "missing"}]}
            )
        missing = [f for f in REQUIRED_FIELDS if f not in body]
        if missing:
            self._record(body, 422, bearer)
            return self._json(
                422,
                {
                    "detail": [
                        {"loc": ["body", f], "msg": "Field required", "type": "missing"} for f in missing
                    ]
                },
            )

        state = body["state"]
        text = state_text(state)
        if "JEV-500-TEST" in text:
            self._record(body, 500, bearer)
            return self._json(500, {"detail": "Internal Server Error"})
        self._record(body, 200, bearer)
        if "JEV-SLOW-TEST" in text:
            time.sleep(SLOW_SECONDS)
        if "SLOW-1S-TEST" in text:
            time.sleep(1.0)

        questions = body["questions"] if isinstance(body["questions"], dict) else {}
        score = ATTACK_SCORE if "ATTACKTEST" in text else BENIGN_SCORE
        if "JEV-UNCERTAIN-TEST" in text:
            score = UNCERTAIN_SCORE
        answers = {}
        for qid, q in questions.items():
            if isinstance(q, dict) and q.get("type") == "noul":
                answers[qid] = {"type": "noul", "noul": score}
        return self._json(
            200,
            {
                "model": "jev-stub",
                "answers": answers,
                "usage": {"input_tokens": len(text) // 4, "output_tokens": 20 * len(questions)},
            },
        )


if __name__ == "__main__":
    print(f"stub-jev listening on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
