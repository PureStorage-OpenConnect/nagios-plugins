#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
#
# * Overview
#
# This simple Nagios/Icinga plugin code can be used to monitor Pure Storage FlashArrays.
# The Pure Storage Python REST Client is used to query the FlashArray performance counters. An optional parameter
# allow to check a single volume instead than the whole flasharray
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#

"""Pure Storage FlashArray performance indicators

   Nagios plugin to retrieve the six (6) basic KPIs from a Pure Storage FlashArray.
   Bandwidth counters (read/write), IOPs counters (read/write) and latency (read/write) are collected from the
   target FA using the REST call.
   The plugin has two mandatory arguments:  'endpoint', which specifies the target FA and 'apitoken', which
   specifies the autentication token for the REST call session. A third optional parameter, 'volname' can
   be used to check a specific named volume.
   The plugin accepts multiple warning and critical threshold parameters in a positional fashion:
      1st threshold refers to write latency
      2nd threshold refers to read latency
      3rd threshold refers to write bandwidth
      4th threshold refers to read bandwidth
      5th threshold refers to write IOPS
      6th threshold refers to read IOPS

"""

import argparse
import logging
import logging.handlers
import nagiosplugin
from pypureclient import flasharray, PureError

# Disable warnings using urllib3 embedded in requests or directly
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PureFAperf(nagiosplugin.Resource):
    """Pure Storage FlashArray performance indicators

    Get the six global KPIs of the flasharray and stores them in the
    metric objects
    """

    def __init__(self, endpoint, apitoken, volname=None):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.volname = volname
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        if (self.volname is None):
            return 'PURE_FA_PERF'
        else:
            return 'PURE_FA_VOL_PERF'

    def get_perf(self):
        """Get performance counters from flasharray."""
        try:
            client = flasharray.Client(target=self.endpoint,
                                       api_token=self.apitoken,
                                       user_agent='Pure_Nagios_plugin/0.2')
            if (self.volname is None):
                res = client.get_arrays_performance()
            else:
                res = client.get_volumes_performance(names=[self.volname])
            if isinstance(res, flasharray.ValidResponse):
                fainfo = res.items
        except Exception as e:
            raise nagiosplugin.CheckError('FA REST call returned "{}"'.format(e))
        return(list(fainfo))

    def probe(self):
        fainfo = self.get_perf()
        if not fainfo:
            return []
        wlat = int(fainfo.usec_per_write_op)
        rlat = int(fainfo.usec_per_read_op)
        wbw = int(fainfo.write_bytes_per_sec)
        rbw = int(fainfo.read_bytes_per_sec)
        wiops = int(fainfo.writes_per_sec)
        riops = int(fainfo.reads_per_sec)
        if (self.volname is None):
            mlabel = 'FA_'
        else:
            mlabel = self.volname + '_'

        metrics = [
                    nagiosplugin.Metric(mlabel + 'wlat', wlat, 'us', min=0, context='wlat'),
                    nagiosplugin.Metric(mlabel + 'rlat', rlat, 'us', min=0, context='rlat'),
                    nagiosplugin.Metric(mlabel + 'wbw', wbw, min=0, context='wbw'),
                    nagiosplugin.Metric(mlabel + 'rbw', rbw, min=0, context='rbw'),
                    nagiosplugin.Metric(mlabel + 'wiops', wiops, min=0, context='wiops'),
                    nagiosplugin.Metric(mlabel + 'riops', riops, min=0, context='riops')
                  ]
        return metrics


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FA hostname or ip address")
    argp.add_argument('apitoken', help="FA api_token")
    argp.add_argument('--vol', help="FA volme. If omitted the whole FA performance counters are checked")
    argp.add_argument('--tw', '--ttot-warning', metavar='RANGE[,RANGE,...]',
                      type=nagiosplugin.MultiArg, default='',
                      help="positional thresholds: write_latency, read_latency, write_bandwidth, read_bandwidth, write_iops, read_iops")
    argp.add_argument('--tc', '--ttot-critical', metavar='RANGE[,RANGE,...]',
                      type=nagiosplugin.MultiArg, default='',
                      help="positional thresholds: write_latency, read_latency, write_bandwidth, read_bandwidth, write_iops, read_iops")
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    check = nagiosplugin.Check( PureFAperf(args.endpoint, args.apitoken, args.vol) )
    check.add(nagiosplugin.ScalarContext('wlat', args.tw[0], args.tc[0]))
    check.add(nagiosplugin.ScalarContext('rlat', args.tw[1], args.tc[1]))
    check.add(nagiosplugin.ScalarContext('wbw', args.tw[2], args.tc[2]))
    check.add(nagiosplugin.ScalarContext('rbw', args.tw[3], args.tc[3]))
    check.add(nagiosplugin.ScalarContext('wiops', args.tw[4], args.tc[4]))
    check.add(nagiosplugin.ScalarContext('riops', args.tw[5], args.tc[5]))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
