#!/usr/bin/env python
# Copyright (c) 2018, 2019, 2020, 2022 Pure Storage, Inc.
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
from pypureclient import flasharray, PureError


# Disable warnings using urllib3 embedded in requests or directly
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PureFAhw(nagiosplugin.Resource):
    """Pure Storage FlashArray hardware status

    Retrieve FA hardware components status

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
        if (self.component is None):
            return 'PURE_FA_HW'
        else:
            return 'PURE_FA_HW_' + str(self.component)

    def get_status(self):
        """Get hardware components status from flasharray."""
        fainfo = []
        try:
            client = flasharray.Client(target=self.endpoint,
                                   api_token=self.apitoken,
                                   user_agent='Pure_Nagios_plugin/0.2')
            if self.component is None:
                res = client.get_hardware()
            else:
                res = client.get_hardware(names=[self.component])
            if isinstance(res, flasharray.ValidResponse):
                fainfo = list(res.items)
        except Exception as e:
            raise nagiosplugin.CheckError('FA REST call returned "{}"'.format(e))
        return(fainfo)

    def probe(self):
        fainfo = self.get_status()
        if fainfo:
            failedcomponents = [component for component in fainfo if component.status not  in ['ok', 'not_installed']]

            if failedcomponents:
                metrics = ", ".join([component.name + ': ' + component.status for component in failedcomponents])
                metric = nagiosplugin.Metric(metrics + '. Status', 1, context='default')
            else:
                if self.component is None:
                    metric = nagiosplugin.Metric('All hardware components are OK. Status', 0, context='default' )
                else:
                    metric = nagiosplugin.Metric('{} hardware is OK. Status'.format(self.component), 0, context='default' )
        else:
            metric = None
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
