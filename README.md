```
           _ _ _____    _____                                 
    ____  (_|_) ___/   / ___/_________ _____  ____  ___  _____
   / __ \/ / /\__ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
  / /_/ / / /___/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    
 / .___/_/_//____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
/_/  Scan shares for PII and sensitive information using YARA.
```

# Installation
Download or git clone.

Install dependencies.

# Usage
Supply share(s), credentials, mountpoint and rules.

## Example
```
python3 piis_scanner.py -v -t "\\10.10.10.2\folder" -p /tmp/credentials/user_creds.txt -r rules/default_rule.txt -m /mnt/share
```


**Credential file format**
```
username=xxx
password=xxx
```



**Target file format**
```
\\\\share1\\folder1
\\\\share2\\
\\\\share3\\folder2
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
  * Implement targets file syntax check
  * Implement possibility to specify multiple rule files
* Implement easily parsable output formatting
* Implement possibility to scan other kinds of data sources
  * HTTP listings
  * FTP(S)
  * any mountable share
  * plain old directories
* Replace os.popen and os.system
* Enhance default rule set
* Write verbose documentation
