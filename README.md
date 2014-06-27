Landesk Parser 
===============

I was on a forensics case and saw that there was no entries in the MFT (event logs, A/V logs, etc.) for gsecdump.exe, but then I happened to see some entries in the SOFTWARE hive when I built my timeline and included the SOFTWARE hive in it. They were dropped around the time of initial infections. gsec was scheduled to run via At jobs.

Then I started playing around with the hive and realized there was a lot of value in these entries.

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

              ===================================================
              Host Information
              ===================================================
              Hostname: TESTMACHINE
              IP Addr: 10.10.10.10

              ===================================================
              Login History
              ===================================================
              <user_name> logged in at 2014-05-21 09:45:49
                      GROUP1
                      GROUP2
                      GROUP3
                      ETC....
              <user_name> logged in at 2014-05-22 09:45:49
                      GROUP1
                      GROUP2
                      GROUP3
                      ETC....
              <user_name> logged in at 2014-05-23 09:45:49
                      GROUP1
                      GROUP2
                      GROUP3
                      ETC.... 

              ===================================================
              Application Log
              ===================================================
              <snip>
              App Name: C:/Windows/System32/gse.exe
              Key LWrite: 2013-03-13 08:59:00.802603
              Last Run: 2013-03-13 08:59:00.092000
              First Run: 2013-03-13 08:59:00.092000
              Last Duration: 0.71
              Total Duration: 0.71
              Current User: SYSTEM
              Run count: 1

              App Name: C:/Windows/System32/gsec.exe
              Key LWrite: 2013-04-11 07:57:01.265898
              Last Run: 2013-04-11 07:57:00.795000
              First Run: 2013-04-11 07:57:00.795000
              Last Duration: 0.47
              Total Duration: 0.47
              Current User: SYSTEM
              Run count: 1

              <snip>

Todo
=======
Key

- X = Done
- O = Partially done and implemented
- [ ] = Not started

[ ] Output

- [ ] Jinja2 Templates
- [ ] JSON as default (then include a JSON to CSV script as well.)

[ ] Groups
- [ ] Better handling of the user logon groups. It's simple if statements now...

[ ] Errors
- [ ] Some keys are customs and will be unique to companies/people so I need to figure out a way to take these "useful" ones into account.

[ ] Testing
- [ ] I've only tested two hives.... So I could use some more hives if anyone has some that I can use.

Thanks to:
==============

@williballenthin - http://www.williballenthin.com for writing python-registry, which is what I am using. It's great.
