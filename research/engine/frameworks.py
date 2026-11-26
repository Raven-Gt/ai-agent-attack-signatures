"""Mapping between the experiment labs and the attack frameworks.

Mapping basis: the experiment table plus the user-agent evidence found in the
captured traffic of each lab.
  lab1 = PentAGI, first round (contaminated with operator diagnostic traffic,
         removed and not included in the statistics)
  lab2 = DSH      (1506x Python-urllib/3.13 + 9x WindowsPowerShell, the Windows side client)
  lab3 = DSH      (contains the explicit user agent dsh-pentest-poc/1.0)
  lab4 = DSH      (Windows side and Python-urllib mixed)
  lab5 = PentAGI  (1204x ffuf + 256x curl + Chrome/120, the Kali container tool chain)
  lab6 = PentAGI  (dominated by curl/8.21.0)
  lab7 = PentesterFlow (734x Python-urllib/3.14 + curl)
  lab8 = not used
"""

LAB_FRAMEWORK = {
    "lab1": "PentAGI",
    "lab2": "DSH",
    "lab3": "DSH",
    "lab4": "DSH",
    "lab5": "PentAGI",
    "lab6": "PentAGI",
    "lab7": "PentesterFlow",
    "lab8": None,
}

# Labs included in the statistics (lab1 was removed)
LABS_INCLUDED = ("lab2", "lab3", "lab4", "lab5", "lab6", "lab7")
