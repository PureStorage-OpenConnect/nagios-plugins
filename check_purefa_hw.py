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

"""Pure Storage FlashArray hardware components status

   Nagios plugin to retrieve the current status of hardware components from a Pure Storage FlashArray.
   Hardware status indicators are collected from the target FA using the REST call.
   The plugin has three mandatory arguments:  'endpoint', which specifies the target FA, 'apitoken', which
   specifies the autentication token for the REST call session and 'component', that is the name of the
   hardware component to be monitored. The component must be specified using the internal naming schema of
   the Pure FlashArray: i.e CH0 for the main chassis, CH1 for the secondary chassis (shelf 1), CT0 for controller 0,i
   CT1 for controller 1i, CH0.NVB0 for the first NVRAM module, CH0.NVB1 for the second NVRAM module, CH0.BAY0 for
   the first flash module, CH0.BAY10 for the tenth flash module, CH1.BAY1, for the first flash module on the
   first additional shelf,...

"""

import argparse
import logging
import logging.handlers
import nagiosplugin
import purestorage
import urllib3


class PureFAhw(nagiosplugin.Resource):
    """Pure Storage FlashArray hardware status

    Retrieves FA hardware component status

    """

    def __init__(self, endpoint, apitoken, component):
        self.endpoint = endpoint
        self.apitoken = apitoken
        self.component = component
        self.logger = logging.getLogger(self.name)
        handler = logging.handlers.SysLogHandler(address = '/dev/log')
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    @property
    def name(self):
        return 'PURE_FA_HW_' + str(self.component)

    def get_status(self):
        """Gets hardware element status from flasharray."""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        fainfo={}
        try:
            fa = purestorage.FlashArray(self.endpoint, api_token=self.apitoken)
            if self.component is None:
                fainfo = fa.list_hardware()
            else:
                fainfo = [fa.get_hardware(self.component)]
            fa.invalidate_cookie()
        except Exception as e:
            raise nagiosplugin.CheckError('FA REST call returned "%s" ', e)
        return(fainfo)

    def probe(self):
        fainfo = self.get_status()
        failedcomponents = [component for component in fainfo if not component['status'] in ['ok', 'not_installed']]

        if failedcomponents:
            metrics = ", ".join([component['name'] + ': ' + component['status'] for component in failedcomponents])
            metric = nagiosplugin.Metric(metrics + ' status', 1, context='default')
        else:
            metric = nagiosplugin.Metric('All hardware component(s) are OK' + ' status', 0, context='default' )
        return metric


def parse_args():
    argp = argparse.ArgumentParser()
    argp.add_argument('endpoint', help="FA hostname or ip address")
    argp.add_argument('apitoken', help="FA api_token")
    argp.add_argument('--component', help="FA hardware component, if not specified all components are checked")
    argp.add_argument('-v', '--verbose', action='count', default=0,
                      help='increase output verbosity (use up to 3 times)')
    argp.add_argument('-t', '--timeout', default=30,
                      help='abort execution after TIMEOUT seconds')
    return argp.parse_args()


@nagiosplugin.guarded
def main():
    args = parse_args()
    check = nagiosplugin.Check( PureFAhw(args.endpoint, args.apitoken, args.component) )
    check.add(nagiosplugin.ScalarContext('default', '', '@1:1'))
    check.main(args.verbose, args.timeout)

if __name__ == '__main__':
    main()
