'''
The MIT License (MIT)

Copyright (c) 2014 Patrick Olsen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

Author: Patrick Olsen
Email: patrick.olsen@sysforensics.org
Twitter: @patrickrolsen

Thanks to: https://github.com/williballenthin/python-registry


History:
    - October 2015 - getLogonInfo() added by David Durvaux (@ddurvaux)
'''

from __future__ import division
import base64, binascii, struct, sys
import argparse
from Registry import Registry
from datetime import datetime, timedelta
import csv

def getLogonInfo(reg_soft):
    entries = ["Wow6432Node\\Landesk\\Inventory\\LogonHistory\\Logons",
                "Landesk\\Inventory\\LogonHistory\\Logons"]

    user = None
    login = None
    attributes = None
    result = []
    count = 1

    for en in entries:
        try:
            logon_history = reg_soft.open(en)
            for logon in logon_history.values():
                if logon.value() == None:
                    continue

                # Rebuild information on users
                # WARNING: the current key_time value correspond to the lat
                #          update time of the Logons entry.  It should be change
                #          to correspond to sub-key value but I'm still searching
                #          for the write way to do it.
                key_time = logon_history.timestamp() 
                if count == 1:
                    user = logon.value()
                    count = count +1
                elif count == 2:
                    login = logon.value()
                    count = count +1
                else:
                    attributes = logon.value()
                    result.append([key_time, user, login, attributes])
                    user = None
                    login = None
                    attributes = None
                    count = 1
        except Registry.RegistryKeyNotFoundException as e:
            continue
    return result

def gethostInfo(reg_soft):
    entries = ["Wow6432Node\\LANDesk\\amtmon",
                "LANDesk\\amtmon"]
    for en in entries:
        try:
            amtmon = reg_soft.open(en)
            if amtmon.value("ip").value() != None:
                ip_addr = amtmon.value("ip").value()
            else:
                ip_addr = "None"
            if amtmon.value("hostname").value() != None:
                host = amtmon.value("hostname").value()
            else:
                host = "None"

        except Registry.RegistryKeyNotFoundException as e:
            host = "None"
            ip_addr = "None"

    return host, ip_addr

def getMonitorLog(reg_soft):
    dic_Landesk = {}
    entries = ["Wow6432Node\LANDesk\ManagementSuite\WinClient\SoftwareMonitoring\MonitorLog",
               "LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog"]
    
    for en in entries:
        try:
            logon_hist = reg_soft.open(en)
            for sks in logon_hist.subkeys():
                key = reg_soft.open(en+'\\%s' % (sks.name()))
                app_name = key.name()
                key_time = key.timestamp()
                try:
                    time_convert = struct.unpack("<Q", key.value("Last Started").value())[0]
                    # http://stackoverflow.com/questions/4869769/convert-64-bit-windows-date-time-in-python
                    # Convert this to a function and call it.
                    us = int(time_convert) / 10
                    last_run = datetime(1601,1,1) + timedelta(microseconds=us)
                except: 
                    last_run = "None"
                try:
                    time_convert = struct.unpack("<Q", key.value("First Started").value())[0]
                    # Convert this to a function and call it.
                    us = int(time_convert) / 10
                    first_run = datetime(1601,1,1) + timedelta(microseconds=us)
                except:
                    first_run = "None"
                try:
                    last_duration = struct.unpack("<Q", key.value("Last Duration").value())[0]
                    lduration = last_duration / 10000000
                except:
                    lduration = "None"
                try:
                    total_duration = struct.unpack("<Q", key.value("Total Duration").value())[0]
                    tduration = total_duration / 10000000
                except:
                    tduration = "None"
                try:
                    current_user = key.value("Current User").value()
                except:
                    current_user = "None"
                try:
                    run_runs = key.value("Total Runs").value()
                except:
                    run_runs = "None"

                dic_Landesk[app_name] = str(run_runs), str(key_time), str(first_run), str(last_run), \
                                        str(lduration), str(tduration), current_user
            return dic_Landesk

        except Registry.RegistryKeyNotFoundException as e:
            pass

def outputResults(output, hosts):
    LDwriter = csv.writer(sys.stdout)
    LDwriter.writerow(["Application Name", "Host Name", "IP Address", "Total Runs", "Last Write", "First Run", \
                        "Last Run", "Last Running Duration", "Total Running Duration", \
                        "Current User"])
    for key, value in output.iteritems():
        LDwriter.writerow([key, hosts[0], hosts[1], value[0], value[1], value[2], \
                            value[3], value[4], value[5], value[6]])

def outputLogons(logons):
    LDwriter = csv.writer(sys.stdout)
    LDwriter.writerow(["Time", "User", "User Account", "Groups"])

    for [time, user, account, groups] in logons:
        LDwriter.writerow([time, user, account, groups])


def main():
    parser = argparse.ArgumentParser(description='Parse the Landesk Entries in the Registry.')
    parser.add_argument('-soft', '--software', help='Path to the SOFTWARE hive you want parsed.')

    args = parser.parse_args()

    if args.software:
        reg_soft = Registry.Registry(args.software)
    else:
        print "You need to specify a SOFTWARE hive."

    logons = getLogonInfo(reg_soft)
    outputLogons(logons)
    
    hosts = gethostInfo(reg_soft)
    output = getMonitorLog(reg_soft)
    outputResults(output, hosts)
if __name__ == "__main__":
    main()
    