#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020 Pure Storage, Inc.
#
# * Overview
#
# This short Nagios/Icinga plugin code shows  how to build a simple plugin to monitor Pure Storage FlashArrays.
# The Pure Storage Python REST Client is used to query the FlashArray.
#
# * Installation
#
# The script should be copied to the Nagios plugins directory on the machine hosting the Nagios server or the NRPE
# for example the /usr/lib/nagios/plugins folder.
# Change the execution rights of the program to allow the execution to 'all' (usually chmod 0755).
#
# * Dependencies
#
#  nagiosplugin      helper Python class library for Nagios plugins (https://github.com/mpounsett/nagiosplugin)
#  purestorage       Pure Storage Python REST Client (https://github.com/purestorage/rest-client)

"""Pure Storage FlashArray pod status

   Nagios plugin to retrieve the current status of all pods from a Pure Storage FlashArray.
   Pod array status indicators are collected from the target FA using a REST call.
   Pod write latency indicators are also collected from the target FA using a REST call.
   The plugin has two mandatory arguments:  'endpoint', which specifies the target FA, 'apitoken', which
   specifies the autentication token for the REST call session. Optionally you can specify --pod to check only 
   the pod that is specified. You can use --criticalwritelatency to specify the maximum write latency in ms.

"""

import argparse
import logging
import logging.handlers
import nagiosplugin
import purestorage
import urllib3


class PureFAhw(nagiosplugin.Resource):
    """Pure Storage FlashArray pod status

    Retrieves FA pod status

    """

    def __init__(self, endpoint, apitoken, pod, criticalwritelatency):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.criticalwritelatency = criticalwritelatency
        self.pod = pod
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        if (self.pod is None):
            return 'PURE_FA_POD'
        else:
            return 'PURE_FA_POD_' + str(self.pod)

    def get_status(self, monitor=None):
        """Gets pod status from flasharray."""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        fainfo={}
        try:
            fa = purestorage.FlashArray(self.endpoint, api_token=self.apitoken)
            if self.pod is None:
                if monitor is None:
                    fainfo = fa.list_pods()
                else:
                    fainfo = fa.list_pods(action='monitor', mirrored=True)
            else:
                if monitor is None:
                    fainfo = [fa.get_pod(self.pod)]
                else:
                    fainfo = fa.get_pod(self.pod, action='monitor', mirrored=True)
            fa.invalidate_cookie()
        except Exception as e:
            raise nagiosplugin.CheckError(f'FA REST call returned "{e}"')
        return(fainfo)

    def probe(self):
        podstatus = self.get_status()
        podmetrics = self.get_status(monitor=True)
        failedpods = []
        slowpods = []
        for pod in podstatus:
            failedarrays = [array for array in pod['arrays'] if not array['status'] == 'online']
            if failedarrays:
                failedpods.append({'name': pod['name'], 'array': failedarrays})
        
        for pod in podmetrics:
            if pod['usec_per_mirrored_write_op'] > (int(self.criticalwritelatency) * 1000):
                slowpods.append({'name': pod['name'], 'usec_per_mirrored_write_op': pod['usec_per_mirrored_write_op']})

        if failedpods:
            metrics = ", ".join([f"For pod {pod['name']} " + ", ".join([f"the array {array['name']} is {array['status']}" for array in pod['array']])  for pod in failedpods])
            metric = nagiosplugin.Metric(metrics + ' status', 1, context='default')
            return metric
        elif slowpods:
            metrics = ", ".join([f"Pod {pod['name']} has a write latency of {pod['usec_per_mirrored_write_op'] / 1000} ms." for pod in slowpods])
            metric = nagiosplugin.Metric(metrics + ' status', 1, context='default')
            return metric
        else:
            metric = nagiosplugin.Metric('All pod(s) are OK' + ' status', 0, context='default' )
            return metric


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help='FA hostname or ip address')
    argp.add_argument('apitoken', help='FA api_token')
    argp.add_argument('--pod', help='FA Pod, if not specified all pods are checked')
    argp.add_argument('--criticalwritelatency', default = 3,
                      help='The critical write latency for the pod in ms')
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    check = nagiosplugin.Check( PureFAhw(args.endpoint, args.apitoken, args.pod, args.criticalwritelatency) )
    check.add(nagiosplugin.ScalarContext('default', '', '@1:1'))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
