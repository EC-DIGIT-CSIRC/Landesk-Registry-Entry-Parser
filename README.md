Landesk Parser 
===============

I was on a forensics case and saw that there was no entries in the MFT (event logs, A/V logs, etc.) for gsecdump.exe, but then I happened to see some entries in the SOFTWARE hive when I built my timeline and included the SOFTWARE hive in it. They were dropped around the time of initial infections. gsec was scheduled to run via At jobs.

Then I started playing around with the hive and realized there was a lot of value in these entries.

This is the software: http://www.landesk.com

How to Install
===============

(Going off memory here)

Python

- Python 2.7

Python Registry

- Download: https://github.com/williballenthin/python-registry
- python setup.py build
- python setup.py install

Done...

Running
=========

python landesk-parse.py -h
              
              usage: landesk-parse.py [-h] [-soft SOFTWARE]

              Parse the Landesk Entries in the Registry.

              optional arguments:
                -h, --help            show this help message and exit
                -soft SOFTWARE, --software SOFTWARE
                                      Path to the SOFTWARE hive you want parsed.

python landesk-parse.py -soft SOFTWARE

Output Example
===============

              Application Name,Host Name,IP Address,Total Runs,Last Write,First Run,Last Run,Last Running Duration,Total Running Duration,Curernt User
              C:/MPSigStub.exe,<hostname>,<ip_addr>,2013-04-09 01:57:36.905449,2013-04-09 01:57:30.175000,2013-04-09 01:57:30.175000,6.73,6.73,<current_user>
              //mehmeh/netlogon/IFMEMBER.EXE,<hostname>,<ip_addr>,2014-05-16 00:56:43.197462,2012-07-02 00:42:13.751000,2014-05-16 00:56:42.125000,1.072,5.788,<current_user>
              C:/Windows/System32/sethc.exe,<hostname>,<ip_addr>,1,2012-09-12 08:51:08.714193,2012-09-12 08:50:54.984000,2012-09-12 08:50:54.984000,13.73,13.73,<current_user>

Thanks to:
==============

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I am using. It's great.
