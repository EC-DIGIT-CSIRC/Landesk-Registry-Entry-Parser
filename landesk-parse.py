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
'''
from __future__ import division
import base64, binascii, struct, sys
import argparse
from Registry import Registry
from datetime import datetime, timedelta

parser = argparse.ArgumentParser(description='Parse the Landesk Entries in the Registry.')
parser.add_argument('-soft', '--software', help='Path to the SOFTWARE hive you want parsed.')

args = parser.parse_args()

if args.software:
    reg_soft = Registry.Registry(args.software)
else:
    print "You need to specify a SOFTWARE hive."

def gethostInfo(reg_soft):
    print ("\n" + ("=" * 51) + "\nHost Information\n" + ("=" * 51))
    entries = ["Wow6432Node\\LANDesk\\amtmon",
                "LANDesk\\amtmon"]
    for en in entries:
        try:
            amtmon = reg_soft.open(en)
            try:
                ip_addr = amtmon.value("ip").value()
            except:
                ip_addr = "No IP..."
            try:
                host = amtmon.value("hostname").value()
            except:
                host = "No hostname...."

            print 'Hostname: %s' % (host)
            print 'IP Addr: %s' % (ip_addr)

        except Registry.RegistryKeyNotFoundException as e:
            pass

def getlogonHist(reg_soft):
    print ("\n" + ("=" * 51) + "\nLogin History\n" + ("=" * 51))
    entries = ["Wow6432Node\\LANDesk\\Inventory\\LogonHistory",
                "LANDesk\\Inventory\\LogonHistory"]
    for en in entries:
        try:
            logon_hist = reg_soft.open(en)
            for sks in logon_hist.subkeys():
                if "logons" in sks.name().lower():
                    ########################################################################
                    # This is a terrible way to parse the groups, but it works for now...
                    # I was getting unicode errors on the Asian group names in my test hive.
                    # So I added the encode ignore in there for now...
                    ########################################################################
                    for v in sks.values():
                        if "group" in v.name():
                            g = v.value()
                            for group in g:
                                if 'CN' in group:
                                    if ',OU' in group:
                                        print '\t' + group.split('CN=')[1].split(',OU')[0].encode('ascii', 'ignore')
                                    else:
                                        print '\t' + group.split('CN=')[1].rstrip(',').encode('ascii', 'ignore')
                        else:
                            time = v.name()
                            htime = datetime.fromtimestamp(int(time)).strftime('%Y-%m-%d %H:%M:%S')
                            logins = '%s logged in at %s' % (v.value().split('=')[1].split(',')[0], htime)
                            print logins
        except Registry.RegistryKeyNotFoundException as e:
            pass

def getmonitorLog(reg_soft):
    print ("\n" + ("=" * 51) + "\nApplication Log\n" + ("=" * 51))
    entries = ["Wow6432Node\LANDesk\ManagementSuite\WinClient\SoftwareMonitoring\MonitorLog",
               "LANDesk\\ManagementSuite\\WinClient\\SoftwareMonitoring\\MonitorLog"]
    
    for en in entries:
        try:
            logon_hist = reg_soft.open(en)
            for sks in logon_hist.subkeys():
                key = reg_soft.open(en+'\\%s' % (sks.name()))
                app_name = key.name()
                key_time = key.timestamp()
                # The app name represents the key name.
                print 'App Name: %s' % (app_name)
                # LWrite = Last Write.
                print 'Key LWrite: %s' % (key_time)
                try:
                    last_start_hex = binascii.hexlify((key.value("Last Started").value(), 16)[0])
                    time_convert = struct.unpack("<Q", binascii.unhexlify(last_start_hex))[0]
                    # http://stackoverflow.com/questions/4869769/convert-64-bit-windows-date-time-in-python
                    us = int(time_convert) / 10
                    last_run = datetime(1601,1,1) + timedelta(microseconds=us)
                    print 'Last Run: %s' % (last_run)
                except: 
                    last_run = "No last runs..."
                    print 'Last Run: %s' % (last_run)
                try:
                    first_start_hex = binascii.hexlify((key.value("First Started").value(), 16)[0])
                    time_convert = struct.unpack("<Q", binascii.unhexlify(first_start_hex))[0]
                    us = int(time_convert) / 10
                    first_run = datetime(1601,1,1) + timedelta(microseconds=us)
                    print 'First Run: %s' % (first_run)
                except:
                    first_run = "No first run..."
                    print 'First Run: %s' % (first_run)
                try:
                    last_duration = struct.unpack("<Q", binascii.unhexlify(binascii.hexlify(key.value("Last Duration").value())))[0]
                    lduration = last_duration / 10000000
                    print 'Last Duration: %s' % (lduration)
                except:
                    lduration = "No duration..."
                    print 'Last Duration: %s' % (lduration)
                try:
                    total_duration = struct.unpack("<Q", binascii.unhexlify(binascii.hexlify(key.value("Total Duration").value())))[0]
                    tduration = total_duration / 10000000
                    print 'Total Duration: %s' % (tduration)
                except:
                    tduration = "No duration..."
                    print 'Total Duration: %s' % (tduration)
                try:
                    current_user = key.value("Current User").value()
                    print 'Current User: %s' % (current_user)
                except:
                    current_user = "No user..."
                    print 'Current User: %s' % (current_user)
                try:
                    run_runs = key.value("Total Runs").value()
                    print 'Run count: %s' % (run_runs)
                except:
                    run_runs = "No run count..."
                    print 'Run count: %s' % (run_runs)
                print '\n'
        except Registry.RegistryKeyNotFoundException as e:
            pass

def main():
    gethostInfo(reg_soft)
    getlogonHist(reg_soft)
    getmonitorLog(reg_soft)
if __name__ == "__main__":
    main()