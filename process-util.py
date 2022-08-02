#!/usr/bin/env python

import argparse
import csv
import os
import sys
from datetime import datetime

# Local helpers
from redcanary.responseutils.common import *

# Carbon Black
from cbapi.response import CbEnterpriseResponseAPI
from cbapi.response.models import Process, Sensor
from cbapi.errors import *


_python3 = sys.version_info.major >= 3


def get_process_details(process):
    timestamp = convert_timestamp(process.start)
    hostname = process.hostname.lower()
    username = process.username.lower()
    path = process.path
    cmdline = process.cmdline

    try:
        process_md5 = process.process_md5
    except:
        process_md5 = ''

    return [timestamp,
            hostname,
            username,
            path,
            cmdline,
            process_md5,
            process.childproc_count,
            process.filemod_count,
            process.modload_count,
            process.netconn_count,
            process.webui_link,
            process.parent_name
            ]


def process_search(cb_conn, query, query_base=None, groupby=None):
    if query_base != None:
        query += query_base

    query_result = cb_conn.select(Process).where(query)

    if groupby != None:
        query_result = query_result.group_by(groupby)

    query_result_len = len(query_result)
    log_info('Total results: {0}'.format(query_result_len))

    results = []

    try:
        for process_counter, process in enumerate(query_result, start=1):
            if process_counter % 100 == 0:
                log_info('Processing {0} of {1}'.format(process_counter, query_result_len))

            results.append(get_process_details(process))
    except KeyboardInterrupt:
        log_info("Caught CTRL-C. Returning what we have . . .")

    return tuple(results)


def main():
    parser = build_cli_parser("Process utility")
    parser.add_argument("--groupby", type=str, action="store",
                        help="Group process results")
    args = parser.parse_args()

    # BEGIN Common 
    if args.prefix:
        output_filename = '{0}-processes.csv'.format(args.prefix)
    else:
        output_filename = 'processes.csv'

    file_mode = 'a' if args.append == True or args.queryfile is not None else 'w'
    if args.days:
        query_base = ' start:-{0}m'.format(args.days*1440)
    elif args.minutes:
        query_base = ' start:-{0}m'.format(args.minutes)
    else:
        query_base = ''

    if args.profile:
        cb = CbEnterpriseResponseAPI(profile=args.profile)
    else:
        cb = CbEnterpriseResponseAPI()

    groupby = args.groupby or None
    queries = []
    if args.query:
        queries.append(args.query)
    elif args.queryfile:
        with open(args.queryfile, 'r') as f:
            queries.extend(query.strip() for query in f)
        f.close()
    else:
        queries.append('')
    with open(output_filename, file_mode) as output_file:
        writer = csv.writer(output_file)
        writer.writerow(["proc_timestamp",
                         "proc_hostname",
                         "proc_username",
                         "proc_path",
                         "proc_cmdline",
                         "proc_md5",
                         "proc_child_count",
                         "proc_filemod_count",
                         "proc_modload_count",
                         "proc_netconn_count",
                         "proc_url",
                         "parent_name"
                         ])

        for query in queries:
            result_set = process_search(cb, query, query_base, groupby)

            for row in result_set:
                if _python3 == False:
                    row = [col.encode('utf8') if isinstance(col, unicode) else col for col in row]
                writer.writerow(row)


if __name__ == '__main__':

    sys.exit(main())
