"""Ground truth labels (evaluation only, they never enter the feature set).

Four classes
------------
agent           an AI agent (lab1 PentAGI / lab2 DSH)
script          a fixed script (the happy-path regression script of the lab,
                python-requests, a fixed sequence of 16 requests, 0 s apart)
human_operator  a human operator (an operator probing with curl or a real Edge
                browser, logging in, debugging, clicking around)
noise           container health checks

Labelling basis (decoupled from the detection features)
-------------------------------------------------------
Labels are assigned from the **actor and the client**, never from a behavioural
feature:
  * python-requests/2.32.5  -> the fixed happy-path script (written by us, fixed sequence)
  * curl/8.18.0             -> a human running curl by hand (minutes between requests)
  * Mozilla/... Edg/158     -> a real browser, human browsing
  * 172.26.160.1            -> the agent side (PentAGI / DSH started from a Windows host)
Labelling this way keeps it independent of pause distributions and path entropy,
which avoids "labelling with the thing that is being measured".

**Honest note on the human sample size**: there are only 5 requests in lab1
and 2 in lab2.  That is enough for a qualitative comparison and for calibrating
the false-positive ceiling, but not enough to train on or to give a stable metric.
"""

LAB_AGENT_SRC = {
    "lab1": "172.26.160.1",
    "lab2": "172.26.160.1",
    "lab3": "172.26.160.1",
    "lab4": "172.26.160.1",
    "lab5": "172.26.160.1",
    "lab6": "172.26.160.1",
    "lab7": "172.26.169.59",
    "lab8": "172.26.160.1",
    "csai": "172.34.0.1",
    "autopt": "172.34.0.1",
    "autopt_all": "172.34.0.1",
    "hbgpt": "172.34.0.1",
    "antifox": "172.34.0.1",
    "ptai": "172.34.0.1",
    "raptor": "172.34.0.1",
    "artex": "172.34.0.1",
    "strix": "172.34.0.1",
    "xalgorix": "172.34.0.1",
}

NOISE_SRC = ("127.0.0.1", "::1")

# The same address plays a different role in different labs: 172.26.160.1 is
# the attack source in lab2/3/4, but the operator in lab7 (the attack source of
# PentesterFlow is 172.26.169.59).
LAB_FORCE_NOISE = {
    "lab7": ("172.26.160.1", "172.34.0.1"),
}

SCRIPT_UA = "python-requests/2.32.5"

AGENT_LABELS = ("agent", "agent_pentagi", "agent_dsh")
SCRIPT_LABELS = ("script",)
HUMAN_LABELS = ("human_operator",)


def label_for_request(lab: str, src: str, ua: str) -> str:
    if src in NOISE_SRC:
        return "noise"
    if src in LAB_FORCE_NOISE.get(lab, ()):
        return "noise"
    if lab in LAB_AGENT_SRC and src == LAB_AGENT_SRC[lab]:
        return "agent"
    u = (ua or "").lower()
    if "python-requests" in u:
        return "script"
    if "curl/" in u or "mozilla" in u or "edg/" in u or "chrome" in u:
        return "human_operator"
    if "selftest" in u:
        return "script"
    return "script"


def is_agent(label: str) -> bool:
    return label in AGENT_LABELS or str(label).startswith("agent")


def is_script(label: str) -> bool:
    return label in SCRIPT_LABELS


def is_human(label: str) -> bool:
    return label in HUMAN_LABELS


def is_noise(label: str) -> bool:
    return label == "noise"


# ------------------------------------------------------------- compatibility layer ---
# The older scripts (run_detection / train_models / ablation / compare_methods)
# look the label up by source address.  The three-way classifier uses
# label_for_request(); the address based mapping is kept so that the old flow
# keeps working.
LAB_SRC_LABELS = {
    "lab1": {"172.26.160.1": "agent", "172.28.0.1": "script",
             "172.28.0.10": "script", "127.0.0.1": "noise"},
    "lab2": {"172.26.160.1": "agent", "172.29.0.1": "noise",
             "172.26.169.59": "noise", "172.29.0.10": "noise",
             "127.0.0.1": "noise"},
    "lab3": {"172.26.160.1": "agent", "172.30.0.1": "noise", "127.0.0.1": "noise"},
    "lab4": {"172.26.160.1": "agent", "172.31.0.1": "noise", "127.0.0.1": "noise"},
    "lab5": {"172.26.160.1": "agent", "127.0.0.1": "noise"},
    "lab6": {"172.26.160.1": "agent", "127.0.0.1": "noise"},
    "lab7": {"172.26.169.59": "agent", "172.26.160.1": "noise", "172.34.0.1": "noise", "127.0.0.1": "noise"},
    "lab8": {"172.26.160.1": "agent", "127.0.0.1": "noise"},
}


def labels_for(lab: str) -> dict:
    return LAB_SRC_LABELS.get(lab, {})
