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
python3 piis_scanner.py -t "\\\\\\\\10.10.10.2\\\\folder" -p /tmp/credentials/user_creds.txt -r rules/testrule -m /mnt/share
```


**Credential file format**
```
_username=xxx_
_password=xxx_
```



**Target file format**
```
_\\\\share1\\folder1_
_\\\\share2\\_
_\\\\share3\\folder2_
```

**Rule file format**

See: https://yara.readthedocs.io/en/v3.4.0/writingrules.html

# Dependencies and Credits
YARA for python: https://github.com/VirusTotal/yara-python

# License
tba

# TODO
* Enhance CLI
  * Implement switches for writing results to file
  * Implement credential file syntax check
    * Add hint that path must be absolute
    * Maybe alert on lax file permissions
  * Implement targets file syntax check
  * Implement possibility to specify multiple rule files
  * Implement verbose/silent mode
* Implement easily parsable output formatting
* Implement possibility to scan other kinds of data sources
  * HTTP listings
  * FTP(S)
  * any mountable share
  * plain old directories
* Implement default rule set
* Write verbose documentation
