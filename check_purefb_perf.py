#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
#
# * Overview
#
# This simple Nagios/Icinga plugin code can be used to monitor Pure Storage FlashBlade systems.
# The Pure Storage Python REST Client is used to query the FlashBlade performance counters.
# Plugin leverages the remarkably helpful nagiosplugin library by Christian Kauhaus.
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#

"""Pure Storage FlashBlade performance indicators

   Nagios plugin to retrieve the six (6) basic KPIs from a Pure Storage FlashBlade.
   Bandwidth counters (read/write), IOPs counters (read/write) and latency (read/write) are collected from the
   target FB using the REST call.
   The plugin has two mandatory arguments:  'endpoint', which specifies the target FA and 'apitoken', which
   specifies the autentication token for the REST call session. A third optional parameter, 'protocol' can
   be used to check a specific protocol.
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
from pypureclient import flashblade, PureError

# Disable warnings using urllib3 embedded in requests or directly
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PureFBperf(nagiosplugin.Resource):
    """Pure Storage FlashBlade performance indicators

    Get the six global KPIs of the FlashBlade and stores them in the
    metric objects
    """

    def __init__(self, endpoint, apitoken, proto=None):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.proto = proto
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        if (self.proto=='nfs'):
            return 'PURE_FB_NFS_PERF'
        elif (self.proto=='http'):
            return 'PURE_FB_HTTP_PERF'
        elif (self.proto=='s3'):
            return 'PURE_FB_S3_PERF'
        else:
            return 'PURE_FB_PERF'

    def get_perf(self):
        """Get performance counters from FlashBlade."""
        try:
            client = flashblade.Client(target=self.endpoint,
                                       api_token=self.apitoken,
                                       user_agent='Pure_Nagios_plugin/0.2')
            if self.proto is None:
                res = client.get_arrays_performance(protocol='all')
            else:
                res = client.get_arrays_performance(protocol=self.proto)
            if isinstance(res, flashblade.ValidResponse):
                fbinfo = next(res.items)
        except Exception as e:
            raise nagiosplugin.CheckError('FB REST call returned "{}"'.format(e))
        return(fbinfo)


    def probe(self):

        fbinfo = self.get_perf()
        if fbinfo:
            self.logger.debug('FB REST call returned "%s" ', fbinfo)
            wlat = int(fbinfo.usec_per_write_op)
            rlat = int(fbinfo.usec_per_read_op)
            wbw = int(fbinfo.write_bytes_per_sec)
            rbw = int(fbinfo.read_bytes_per_sec)
            wiops = int(fbinfo.writes_per_sec)
            riops = int(fbinfo.reads_per_sec)
            mlabel = 'FB_'

            metrics = [nagiosplugin.Metric(mlabel + 'wlat', wlat, 'us', min=0, context='wlat'),
                       nagiosplugin.Metric(mlabel + 'rlat', rlat, 'us', min=0, context='wlat'),
                       nagiosplugin.Metric(mlabel + 'wbw', wbw, '', min=0, context='wbw'),
                       nagiosplugin.Metric(mlabel + 'rbw', rbw, '', min=0, context='rbw'),
                       nagiosplugin.Metric(mlabel + 'wiops', wiops, '', min=0, context='wiops'),
                       nagiosplugin.Metric(mlabel + 'riops', riops, '', min=0, context='riops')]
        else:
            metrics = []
        return metrics


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FB hostname or ip address")
    argp.add_argument('apitoken', help="FB api_token")
    argp.add_argument('--proto', choices=('nfs', 'smb', 'http', 's3'), help="FB protocol. If omitted the whole FB performance counters are checked")
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
    check = nagiosplugin.Check( PureFBperf(args.endpoint, args.apitoken, args.proto) )
    check.add(nagiosplugin.ScalarContext('wlat', args.tw[0], args.tc[0]))
    check.add(nagiosplugin.ScalarContext('rlat', args.tw[1], args.tc[1]))
    check.add(nagiosplugin.ScalarContext('wbw', args.tw[2], args.tc[2]))
    check.add(nagiosplugin.ScalarContext('rbw', args.tw[3], args.tc[3]))
    check.add(nagiosplugin.ScalarContext('wiops', args.tw[4], args.tc[4]))
    check.add(nagiosplugin.ScalarContext('riops', args.tw[5], args.tc[5]))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
