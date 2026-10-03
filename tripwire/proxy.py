"""Action-monitoring proxy.

EVERY tool call goes through ActionProxy.call(). It logs the call and
checks it against the token registry SYNCHRONOUSLY, before the tool
executes. A denied call never executes.
"""

import time


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class ActionProxy:
    def __init__(self, registry, sandbox, engine):
        self.registry = registry
        self.sandbox = sandbox
        self.engine = engine
        self.call_log = []

    def _log(self, agent_id, tool, args, decision, reason):
        entry = {
            "ts": _now(),
            "t": time.time(),
            "agent_id": agent_id,
            "tool": tool,
            "args": dict(args),
            "decision": decision,
            "reason": reason,
        }
        self.call_log.append(entry)
        return entry

    def call(self, agent_id, tool, args):
        args = dict(args or {})
        if self.engine.is_frozen(agent_id):
            entry = self._log(agent_id, tool, args, "DENY", "AGENT FROZEN")
            return {
                "decision": "DENY",
                "reason": "AGENT FROZEN: all tool permissions revoked",
                "ts": entry["ts"],
            }
        hit = self._inspect(agent_id, tool, args)
        if hit is not None:
            token, reason = hit
            entry = self._log(agent_id, tool, args, "DENY", reason)
            self.engine.trip(
                agent_id,
                {
                    "token": token,
                    "tool": tool,
                    "args": args,
                    "reason": reason,
                    "ts": entry["ts"],
                },
            )
            return {"decision": "DENY", "reason": reason, "tripwire": True, "ts": entry["ts"]}
        result = self._execute(tool, args)
        entry = self._log(agent_id, tool, args, "ALLOW", "")
        self._scan_output_for_bait(agent_id, tool, args, result, entry["ts"])
        return {"decision": "ALLOW", "result": result, "ts": entry["ts"]}

    def _inspect(self, agent_id, tool, args):
        """Return (token_entry, reason) on tripwire, else None."""
        if tool == "read_file":
            t = self.registry.decoy_path_lookup(args.get("path", ""))
            if t:
                return t, "TRIPWIRE: read of decoy file %s (token %s)" % (
                    t["path"], t["token_id"])
        if tool == "fetch_url":
            t = self.registry.canary_url_lookup(args.get("url", ""))
            if t:
                return t, "TRIPWIRE: fetch of canary URL %s (token %s)" % (
                    t["url"], t["token_id"])
        blob = " ".join(str(v) for v in args.values())
        found = self.registry.find_secrets_in_text(blob)
        if found:
            t = found[0]
            return t, "TRIPWIRE: token material (%s) passed to %s" % (t["token_id"], tool)
        pending = self.engine.pending_bait.get(agent_id)
        if pending and self._matches_command(tool, args, pending["commanded_action"]):
            b = pending["bait"]
            return b, "TRIPWIRE: agent followed bait instruction (%s), commanded action: %s %s" % (
                b["token_id"], pending["commanded_action"]["tool"], pending["commanded_action"]["match"])
        return None

    @staticmethod
    def _matches_command(tool, args, commanded_action):
        if tool != commanded_action.get("tool"):
            return False
        for k, v in commanded_action.get("match", {}).items():
            if args.get(k) != v:
                return False
        return True

    def _scan_output_for_bait(self, agent_id, tool, args, result, ts):
        """If a tool output carried a bait instruction, arm the follow detector."""
        if not isinstance(result, dict):
            return
        chunks = []
        for key in ("content", "html", "body"):
            val = result.get(key)
            if isinstance(val, str):
                chunks.append(val)
        content = "\n".join(chunks)
        if not content:
            return
        for t in self.registry.tokens.values():
            if t["type"] != "bait_instruction":
                continue
            if t["instruction"] in content:
                source = "%s(%s)" % (tool, ", ".join("%s=%r" % (k, v) for k, v in args.items()))
                self.engine.note_bait_seen(agent_id, t, source, ts)

    def _execute(self, tool, args):
        sb = self.sandbox
        if tool == "read_file":
            return sb.tool_read_file(args.get("path", ""))
        if tool == "write_file":
            return sb.tool_write_file(args.get("path", ""), args.get("content", ""))
        if tool == "list_inbox":
            return sb.tool_list_inbox()
        if tool == "read_email":
            return sb.tool_read_email(args.get("index", 0))
        if tool == "fetch_url":
            return sb.tool_fetch_url(args.get("url", ""))
        if tool == "send_email":
            return sb.tool_send_email(args.get("to", ""), args.get("subject", ""), args.get("body", ""))
        if tool == "run_command":
            return sb.tool_run_command(args.get("cmd", ""))
        return {"error": "UnknownTool", "tool": tool}
