#!/usr/bin/env python
#
#The MIT License (MIT)
##
# Copyright (c) 2015 Bit9 + Carbon Black
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----------------------------------------------------------------------------
#  <Short Description>
#
# Usage: process_netconn_rate.py [options]
#
# High avg. netconn/second alert
#
# Options:
#  -h, --help            show this help message and exit
#  -c SERVER_URL, --cburl=SERVER_URL
#                        CB server's URL.  e.g., http://127.0.0.1
#  -a TOKEN, --apitoken=TOKEN
#                       API Token for Carbon Black server
#  -n, --no-ssl-verify   Do not verify server SSL certificate.
#  -g GT_COUNT, --gt-count=GT_COUNT
#                        Filter processes with greater than [--gt-count]
#                        network events
#  -r CONN_RATE, --rate=CONN_RATE
#                        Alert on processes with more than [--rate] network
#                        connections per second
#  -s, --skip_unknown    Skip processes with unknown start or last update
#
# simple script to detect processes with a high rate of network connections per second
#
#   -Optionally control the minimum total number of connections with the '-g' flag 
#       (defaults to > 100)
#   -Optionally control the rate of connections that will generate an alert with the '-r'
#       flag (defaults to > 100 connections/second)
#   -In testing there were some cases that could not identify either a process start time
#       or a process last update time the '-s' flag provide the option to show or hide
#       such processes (defaults to showing those processes)
#
#


import datetime,pprint
from cbapi.util.cli_helpers import main_helper


def main(cb,args):
    #get all processes with greater than 100 netconns
    procs = cb.process_search(r"netconn_count:[%d TO *]"%args['gt_count'],rows=100)


    for proc in procs['results']:
        events = cb.process_events(proc['id'],proc['segment_id'])
        try:
            start = datetime.datetime.strptime(proc['start'],"%Y-%m-%dT%H:%M:%S.%fZ")
            end = datetime.datetime.strptime(proc['last_update'], "%Y-%m-%dT%H:%M:%S.%fZ")
            runtime = int((end-start).total_seconds())
        except:
            # there were some unknown processes with no known start time or 
            # no known last update
            if not args['skip_unknown']:
                runtime=1
            else:
                continue
        
        rate = proc['netconn_count']/float(runtime)
        if rate > int(args['conn_rate']):
            url = '%s/#analyze/%s/%s'%(args['server_url'],proc['id'],proc['segment_id'])
            print "%s|%s|%.4f"%(url,
                                    proc['process_name'],rate)


if __name__ == "__main__":
    optional_arg = [("-g","--gt-count","store",100,"gt_count","Filter processes with greater than [--gt-count] network events"),("-r","--rate","store",100.0,"conn_rate","Alert on processes with more than [--rate] network connections per second"),
                    ("-s","--skip_unknown","store_true",False,"skip_unknown","Skip processes with unknown start or last update")]

    main_helper("High avg. netconn/second alert",main,custom_optional=optional_arg)


