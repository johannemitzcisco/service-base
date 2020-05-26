# -*- mode: python; python-indent: 4 -*-
import ncs
import ncs.maapi
from ncs.application import Service, PlanComponent
from ncs.dp import Action
import _ncs.dp
import requests
import traceback
from time import sleep
import collections
import netaddr
import _ncs


class InitializeIPAddressPool(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info('*************************************** action name: ', name)
        try:
            maapi = ncs.maapi.Maapi()
            maapi.attach2(0, 0, uinfo.actx_thandle)
            trans = ncs.maapi.Transaction(maapi, uinfo.actx_thandle)
            network = ncs.maagic.get_node(trans, kp)
            if network.resource_pool.name is None:
                network.resource_pool.name = network_name
            self.log.info('Creating IP Resource Pool: '+network.resource_pool.name)
            vars = ncs.template.Variables()
            template = ncs.template.Template(network)
            template.apply('resource-ip-pool', vars)
            result = "Resource Pool Creation Successful"
        except Exception as error:
            self.log.info(traceback.format_exc())
            result = 'Error Creating IP Resouces pool: ' + str(error)
        finally:
            output.result = result

class AllocateIPAddresses(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info('**  action name: ', name, ' ', kp)
        try:
            maapi = ncs.maapi.Maapi()
            maapi.attach2(0, 0, uinfo.actx_thandle)
            trans = ncs.maapi.Transaction(maapi, uinfo.actx_thandle)
            allocation = ncs.maagic.get_node(trans, kp)
            resource_pool = allocation._parent._parent
            ip_list = list(netaddr.iter_iprange('1.1.1.0', '1.1.1.{}'.format(int(input.address_count)-1)))
            prefixlen = netaddr.cidr_merge(ip_list)[0].prefixlen
            self.log.info('Allocating IP Addresses: '+allocation.name)
            vars = ncs.template.Variables()
            vars.add('ADDRESS-POOL', resource_pool.name);
            vars.add('ALLOCATION-NAME', allocation.name);
            vars.add('ALLOCATING-USERNAME', uinfo.username);
            vars.add('ALLOCATING-SERVICE', input.allocating_service)
            vars.add('SUBNET-SIZE', prefixlen);
            template = ncs.template.Template(resource_pool)
            template.apply('ip-address-allocation', vars)
            result = "Network Allocation Successful"
        except Exception as error:
            self.log.info(traceback.format_exc())
            result = 'Error Allocating IP Adresses: ' + str(error)
        finally:
            output.result = result

class CheckReady(Action):
    @Action.action
    def cb_action(self, uinfo, name, kp, input, output):
        self.log.info('************** action name: ', name)
        try:
            result = 'Not Allocated'
            maapi = ncs.maapi.Maapi()
            maapi.attach2(0, 0, uinfo.actx_thandle)
            trans = ncs.maapi.Transaction(maapi, uinfo.actx_thandle)
            allocation = ncs.maagic.get_node(trans, kp)
            network = allocation._parent._parent._parent
            self.log.info('Checking IP allocation on Pool {}, Allocation {}, Network {}' \
                          .format(network.resource_pool.name, 
                          allocation.name, network.name))
            with ncs.maapi.single_read_trans(uinfo.username, uinfo.context,
                                              db=ncs.OPERATIONAL) as op_trans:
                op_root = ncs.maagic.get_root(op_trans)
                ip_allocation_subnet = op_root.resource_pools.ip_address_pool[network.resource_pool.name] \
                                .allocation[allocation.name].response.subnet
            self.log.info('Subnet: ', ip_allocation_subnet)
            if ip_allocation_subnet is not None:
                ip_list = list(netaddr.IPNetwork(ip_allocation_subnet))
                allocation.first_address = str(ip_list[0])
                allocation.last_address = str(ip_list[len(ip_list)-1])
                self.log.info('Network {} has allocation subnet {} {}-{}'.format(network.name, ip_allocation_subnet, \
                               allocation.first_address, allocation.last_address))
                result = "Allocation Successful"
        except KeyError as error:
            self.log.info('Key Error, this is expected before allocation is commited')
            result = 'Not Allocated'
        except Exception as error:
            self.log.info(traceback.format_exc())
            result = 'Error Checking on IP Address Allocation: ' + str(error)
            raise Exception(result)
        finally:
            output.result = result

class Main(ncs.application.Application):
    def setup(self):
        self.log.info('Main RUNNING')
        self.register_action('service-base-initializeIPAddressPool-action', InitializeIPAddressPool)
        self.register_action('service-base-allocateIPAddresses-action', AllocateIPAddresses)
        self.register_action('service-base-checkReady-action', CheckReady)

    def teardown(self):
        self.log.info('Main FINISHED')

