# piiS-scanner
A tool to leverage YARA rules to recursively search for sensitive information in files hosted on shared drives.

# Usage
Supply share, credentials, mountpoint and rules as seen in the example.

# Dependencies and Credits
YARA for python

# License
tba

# TODO
* Implement CLI
  * Implement help menu
  * Implement switches for
    * Writing results to file
    * Supplying file with credentials
    * Supplying file with targets
    * Supplying targets inline
    * Supplying file or directory with rules to apply
    * Supplying rules inline
    * Being verbose or silent
* Implement easily parsable output formatting
* Implement possibility to scan other kinds of shares
* Implement default rulse set
