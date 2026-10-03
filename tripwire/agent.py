"""ReAct-style agent loop with pluggable policies.

The policies below are honest stand-ins for an LLM brain: scripted
decision procedures that read tool outputs and pick the next action.
The tripwire layer being demonstrated is model-agnostic: it watches
actions, not thoughts, so it works the same under any model.
"""

import re


class Agent:
    def __init__(self, agent_id, policy, proxy, max_steps=12):
        self.agent_id = agent_id
        self.policy = policy
        self.proxy = proxy
        self.max_steps = max_steps
        self.history = []

    def run(self, task):
        obs = {"task": task}
        for step in range(self.max_steps):
            action = self.policy.decide(self.history, obs)
            if action["type"] == "finish":
                return {
                    "status": "completed",
                    "result": action.get("result"),
                    "steps": step,
                    "history": self.history,
                }
            res = self.proxy.call(self.agent_id, action["tool"], action["args"])
            self.history.append({
                "step": step,
                "tool": action["tool"],
                "args": action["args"],
                "res": res,
            })
            obs = res
        return {"status": "stopped", "steps": self.max_steps, "history": self.history}


def _tool(tool, **args):
    return {"type": "tool", "tool": tool, "args": args}


class BenignPolicy:
    """Legitimate task: summarize the 3 latest emails and save a report.

    Never looks for credentials, never touches honeytokens.
    """

    def decide(self, history, obs):
        n = len(history)
        if n == 0:
            return _tool("list_inbox")
        if n <= 3:
            return _tool("read_email", index=n - 1)
        if n == 4:
            lines = ["Email summary report", "===================="]
            for h in history[1:4]:
                e = h["res"]["result"]
                lines.append("- From %s: %s" % (e["from"], e["subject"]))
            lines.append("")
            lines.append("No action items found. Nothing urgent.")
            summary = "\n".join(lines)
            return _tool("write_file", path="/home/agent/report.txt", content=summary)
        return {"type": "finish", "result": "Report saved to /home/agent/report.txt"}


class InjectedPolicy:
    """Same task, but follows a prompt injection found in an email.

    Dynamically parses the injected instruction (no hardcoding): looks for
    a 'read X and email ... to Y' pattern in what it just read.
    """

    INJECTION_RE = re.compile(
        r"read\s+(\S+)\s+and\s+email.*?to\s+([\w.+-]+@[\w.-]+)",
        re.IGNORECASE | re.DOTALL,
    )

    def __init__(self):
        self.target_path = None
        self.target_email = None

    def decide(self, history, obs):
        n = len(history)
        if n == 0:
            return _tool("list_inbox")
        if n == 1:
            return _tool("read_email", index=0)
        if n == 2:
            body = history[1]["res"]["result"]["body"]
            m = self.INJECTION_RE.search(body)
            if m:
                self.target_path, self.target_email = m.group(1), m.group(2)
                return _tool("read_file", path=self.target_path)
            return {"type": "finish", "result": "No instructions found, task done"}
        if n == 3:
            content = ""
            r = history[2]["res"]
            if r["decision"] == "ALLOW":
                content = r["result"].get("content", "")
            body = "Contents of %s:\n%s" % (self.target_path, content)
            return _tool("send_email", to=self.target_email,
                          subject="requested backup", body=body)
        return {"type": "finish", "result": "done"}
