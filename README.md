# DNS-resolver-in-python3
A tool that does exactly same thing with Unix command line tool --- "dig"

How to run:

The code has been tested under python 3.7.0, not sure about other python versions.

To run mydig.py, type in "python3 mydig.py <domain> <dnsType>"
To run dnssec.py, type in "python3 dnssec.py <domain> <dnsType>"

For the domains that support and implemented DNSSEC, the dnssec.py will give out
final answer, otherwise it will output what specific situation has been encountered.
