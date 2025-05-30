# PAN Rapid Check

Simple(you should probably just do this in bash with grep) PANOS support file checker that extracts some places to look for CVE-2024-3400 IoCs

Generate the support file from 
Device -> Support -> Generate Tech Support file

iocs.txt should include IPs/hosts from known bad for example https://github.com/volexity/threat-intel/blob/main/2024/2024-04-12%20Palo%20Alto%20Networks%20GlobalProtect/indicators/iocs.csv

## Usage

Run the parser on a tech support file archive:

```bash
python panparse.py support.tgz
```

The script will extract the archive and search the logs based on the
indicators from `iocs.txt`.

## License

This project is licensed under the [MIT License](LICENSE).
