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

Revision History of changes done by David Durvaux for EC DIGIT CSIRC:
  (Twitter: @ddurvaux - Email: david@autopsit.org)
    - 20th October 2015 
        - getLogonInfo() added
    - 27th October 2015 
        - add support for local sqlite file

TODO:
    - add XML PARSING  (c/ProgramData/LANDesk/ManagementSuite/landesk/files)
    - add correlation between registry, sqlite and XML files
    - support for PLASO
'''

from __future__ import division
import base64, binascii, struct, sys, os
import argparse
from Registry import Registry
from datetime import datetime, timedelta
import csv
import sqlite3

def parseXMLFiles(path):
    #TODO
    return

def getSQLiteCacheInfo(sqlite_path):
    conn = sqlite3.connect(sqlite_path)
    tables = [
                "ClientOperations",
                "LastPolicyResponse",
                "LastPolicyTargets",
                "PackageDownloadInfo",
                "RemoteOperation",
                "Targets",
                "TaskHistory"]
    cacheInfo = {}
    for table in tables:
        cacheInfo[table] = extractAllFromTable(conn, table)
    return cacheInfo

def extractAllFromTable(sqlite, table):
    cursor = sqlite.cursor()
    
    # get columns names
    cursor.execute("PRAGMA table_info(%s);" % (table))
    columns = []
    data = []
    for [cid, name, ctype, notnull, dflt_value, pk] in cursor.fetchall():
        columns.append(name)
    data.append(columns)

    # get data
    cursor.execute("SELECT * FROM `%s`;" % (table))
    for row in cursor.fetchall():
        data.append(row)
        
    # return all
    return data

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

def outputSQLResults(table, outfile=sys.stdout):
    LDWriter = csv.writer(outfile)
    LDWriter.writerow(table[0])
    for row in table[1:]:
        LDWriter.writerow(row)

def outputResults(output, hosts, outfile=sys.stdout):
    LDwriter = csv.writer(outfile)
    LDwriter.writerow(["Application Name", "Host Name", "IP Address", "Total Runs", "Last Write", "First Run", \
                        "Last Run", "Last Running Duration", "Total Running Duration", \
                        "Current User"])
    for key, value in output.iteritems():
        LDwriter.writerow([key, hosts[0], hosts[1], value[0], value[1], value[2], \
                            value[3], value[4], value[5], value[6]])

def outputLogons(logons, outfile=sys.stdout):
    LDwriter = csv.writer(outfile)
    LDwriter.writerow(["Time", "User", "User Account", "Groups"])

    for [time, user, account, groups] in logons:
        LDwriter.writerow([time, user, account, groups])


def main():
    # Argument definition
    parser = argparse.ArgumentParser(description='Parse the Landesk Entries in the Registry.')
    parser.add_argument('-soft', '--software', help='Path to the SOFTWARE hive you want parsed.')
    parser.add_argument('-ldc', '--ldclient', help='Path to the LDClientdB.db3 file you want parsed.')
    parser.add_argument('-xml', '--xml_repository', help='Path to the XML directory of Landesk.')
    parser.add_argument('-out', '--output_directory', help='Directory where to wrote all information extracted from Landesk (by default stdout)')


    args = parser.parse_args()

    # Check if an output directory is set
    directory = None
    outfile = None
    if args.output_directory:
        directory = os.path.dirname(args.output_directory)
        if not os.path.exists(directory):
                os.makedirs(directory)
    else:
        outfile = sys.stdout

    # Parse registry entry of Landesk
    if args.software:
        reg_soft = Registry.Registry(args.software)

        # Parse logon informations
        if(directory is not None):
            outfile = open("%s/%s" % (directory, "logons.csv"), "w") 
        logons = getLogonInfo(reg_soft)
        outputLogons(logons, outfile)
        if(directory is not None):
            outfile.close()

        # Parse hosts and monitor log    
        if(directory is not None):
            outfile = open("%s/%s" % (directory, "host-and-monitor.csv"), "w") 
        hosts = gethostInfo(reg_soft)
        output = getMonitorLog(reg_soft)
        outputResults(output, hosts, outfile)
        if(directory is not None):
            outfile.close()

    # Parse local sqlite cache
    if args.ldclient:   
        cacheinfo = getSQLiteCacheInfo(args.ldclient)
        for key in cacheinfo.keys():
            if(directory is not None):
                outfile = open("%s/%s.csv" % (directory, key), "w") 

            table = cacheinfo[key]
            outputSQLResults(table, outfile)

            if(directory is not None):
                outfile.close()
    
    # Parse local XML cache
    if args.xml_repository:
        xmlcache = parseXMLFiles(args.xml_repository)
        #TOOD write result

    # One or both option should be set, otherwise, print the manual ;)
    if not args.software and not args.ldclient and not args.xml_repository:
        print "You need to specify a SOFTWARE hive and/or a SQLITE file and/or a XML repository."

if __name__ == "__main__":
    main()
    