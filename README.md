# PAN Rapid Check

Simple(you should probably just do this in bash with grep) PANOS support file checker that extracts some places to look for CVE-2024-3400 IoCs

Generate the support file from
Device -> Support -> Generate Tech Support file

iocs.txt should include IPs/hosts from known bad for example https://github.com/volexity/threat-intel/blob/main/2024/2024-04-12%20Palo%20Alto%20Networks%20GlobalProtect/indicators/iocs.csv

## Setup

This repository includes a `requirements.txt` file listing the Python
dependencies. Install them using `pip`:

```bash
pip install -r requirements.txt
```
