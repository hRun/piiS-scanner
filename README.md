```
           _ _ _____    _____                                 
    ____  (_|_) ___/   / ___/_________ _____  ____  ___  _____
   / __ \/ / /\__ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  / /_/ / / /___/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    
 / .___/_/_//____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
/_/  Scan shares for PII and sensitive information using YARA.
```

This tool is intended to help you with threat hunting, auditing or IoC collection by enabling you to scan files on remote shares for pii and sensitive information such as passwords or keys. Scanning capabilities for HTTP directory listings and FTP will be added.

# Setup
Simply download and unpack or git clone.

Make sure you meet all dependencies.
* Python 3.x
* yara-python

# Usage
Supply share(s), credentials, mountpoint and rules as well as optional arguments.

```
piis_scanner.py [-h] [-v] -m MOUNT -r RULES [-p PWD] [-s SHARES] [-t TARGET] [-w]

  -h, --help                  show this help message and exit
  -v, --verbose               Write verbose output
  -m MOUNT, --mount MOUNT     Absolute path where to temporarily mount shares to
  -r RULES, --rules RULES     File to read YARA rules from
  -p PWD, --pass PWD          File to read credentails for authentication from (absolute path)
  -s SHARES, --shares SHARES  File to read multiple shares to scan from
  -t TARGET, --target TARGET  Share to scan. Enclosed in single quotes. Will be overridden by -s|--shares if specified
  -w, --write                 Write output to file instead of stdout

```

## Examples
```
python3 piis_scanner.py -v -t '\\10.10.10.2\folder' -p /tmp/credentials/user_creds.txt -r rules/default_rule.txt -m /mnt/share
```
```
python3 piis_scanner.py -w -s /tmp/targets -p /tmp/credentials/user_creds.txt -r rules/default_rule.txt -m /mnt/share
```

**Credential file format**
```
username=xxx
password=xxx
```



**Target file format**
```
\\share1\folder1
\\share2\
\\share3\folder2
# \\share4\folder3 This one will be skipped
```

**Rule file format**

See: https://yara.readthedocs.io/en/v3.4.0/writingrules.html

# Dependencies and Credits
YARA for python: https://github.com/VirusTotal/yara-python

# License
tba

# TODO
* Enhance CLI
  * Implement credential file syntax check
    * Add hint that path must be absolute
    * Maybe alert on lax file permissions
  * Implement possibility to specify multiple rule files
  * Implement switch to specify (wildcard) exceptions
* Implement sanity check on specified mountpoint
* Implement easily parsable output formatting
* Implement possibility to scan other kinds of data sources
  * HTTP listings
  * FTP(S)
  * any mountable share
  * plain old directories
* Enhance default rule set
* Compatibility for Windows
* Write verbose documentation
* Lots of bug fixing
