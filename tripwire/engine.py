"""Tripwire engine: freezes hijacked agents and emits structured alerts."""

import time


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class TripwireEngine:
    def __init__(self):
        self.frozen = set()
        self.alerts = []
        self.pending_bait = {}
        self._alert_seq = 0

    def is_frozen(self, agent_id):
        return agent_id in self.frozen

    def note_bait_seen(self, agent_id, bait, source, ts):
        """A tool output just carried a bait instruction: arm the follow detector."""
        if self.is_frozen(agent_id):
            return
        self.pending_bait[agent_id] = {
            "bait": bait,
            "commanded_action": bait["commanded_action"],
            "source": source,
            "ts": ts,
        }

    def trip(self, agent_id, evidence):
        """Instantly freeze the agent and emit a structured alert."""
        self.frozen.add(agent_id)
        self._alert_seq += 1
        token = evidence["token"]
        pending = self.pending_bait.get(agent_id)
        chain = []
        if pending:
            chain.append(
                "1. %s at %s: tool output carried bait instruction (token %s)"
                % (pending["source"], pending["ts"], pending["bait"]["token_id"])
            )
            step = 2
        else:
            chain.append("1. No bait preamble observed: agent went straight for the token")
            step = 2
        chain.append(
            "%d. %s at %s: attempted %s(%s)"
            % (step, agent_id, evidence["ts"], evidence["tool"],
               ", ".join("%s=%r" % (k, v) for k, v in evidence["args"].items()))
        )
        chain.append(
            "%d. Proxy matched %s token %s -> DENY, agent frozen, permissions revoked"
            % (step + 1, token["type"], token["token_id"])
        )
        alert = {
            "alert_id": "AL-%04d" % self._alert_seq,
            "timestamp": evidence["ts"],
            "agent_id": agent_id,
            "severity": token["severity"],
            "event": "TRIPWIRE",
            "token_id": token["token_id"],
            "token_type": token["type"],
            "token_location": token["location"],
            "action_attempted": "%s(%s)" % (
                evidence["tool"],
                ", ".join("%s=%r" % (k, v) for k, v in evidence["args"].items())),
            "injection_source": pending["source"] if pending else "unknown (direct access)",
            "evidence_chain": chain,
            "response": "Agent frozen instantly: all tool permissions revoked in the proxy",
        }
        self.alerts.append(alert)
        return alert

    def reset(self):
        self.frozen.clear()
        self.alerts.clear()
        self.pending_bait.clear()
        self._alert_seq = 0
