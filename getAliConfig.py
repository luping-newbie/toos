#!/usr/bin/env python
# coding=utf-8
"This script are supposed to get your ECS config from Ali Cloud by your ECS tag"

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkecs.request.v20140526 import DescribeInstancesRequest
from aliyunsdkecs.request.v20140526 import DescribeDisksRequest
from aliyunsdkecs.request.v20140526 import DescribeSecurityGroupAttributeRequest
from aliyunsdkecs.request.v20140526 import StopInstanceRequest
from aliyunsdkvpc.request.v20160428 import DescribeVpcsRequest
from aliyunsdkvpc.request.v20160428 import DescribeVSwitchesRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancersRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerAttributeRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerHTTPListenerAttributeRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerTCPListenerAttributeRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerUDPListenerAttributeRequest
from aliyunsdkslb.request.v20140515 import DescribeLoadBalancerHTTPSListenerAttributeRequest
from aliyunsdkslb.request.v20140515 import DescribeVServerGroupsRequest
from aliyunsdkslb.request.v20140515 import DescribeVServerGroupAttributeRequest
import json
import sys
import configparser

# 获取VPC信息
def getVpcInfo(simple_instance, client):
    request = DescribeVpcsRequest.DescribeVpcsRequest()
    request.set_VpcId(simple_instance['VpcId'])
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    vpc = {}
    vpc['vpc_cidr_blocks'] = responseStr['Vpcs']['Vpc'][0]['CidrBlock']
    vpc['vpc_name'] = responseStr['Vpcs']['Vpc'][0]['VpcName']
    simple_instance['vpc'] = vpc

# 获取子网信息
def getSubnetInfo(simple_instance, client):
    request = DescribeVSwitchesRequest.DescribeVSwitchesRequest()
    request.set_VSwitchId(simple_instance['VSwitchId'])
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    subnet = {}
    subnet['subnet_cidr'] = responseStr['VSwitches']['VSwitch'][0]['CidrBlock']
    subnet['subnet_name'] = responseStr['VSwitches']['VSwitch'][0]['VSwitchName']
    simple_instance['subnet'] = subnet

# 获取磁盘信息
def getDiskInfo(simple_instance, client):
    request = DescribeDisksRequest.DescribeDisksRequest()
    request.set_InstanceId(simple_instance['InstanceId'])
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    DiskSet = responseStr['Disks']['Disk']
    simple_DiskSet = []
    for disk in DiskSet:
        diskInfo = {}
        diskInfo['Type'] = disk['Type']
        diskInfo['Size'] = disk['Size']
        diskInfo['Category'] = disk['Category']
        diskInfo['DiskName'] = disk['DiskName']
        diskInfo['Device'] = disk['Device']
        simple_DiskSet.append(diskInfo)
    simple_instance['disks'] = simple_DiskSet
# 获取防火墙规则
def getSecurityGroup(simple_instance, client):
    request = DescribeSecurityGroupAttributeRequest.DescribeSecurityGroupAttributeRequest()
    rules=[]
    for sg_id in simple_instance['SecurityGroupIds']:
        request.set_SecurityGroupId(sg_id)
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        rules = rules + responseStr['Permissions']['Permission']
    simple_rules=[]
    for rule in rules:
        # 只还原入向的防火墙规则
        if rule['Direction'] == 'ingress':
            simple_rule = {}
            simple_rule['SourceCidrIp'] = rule['SourceCidrIp']
            simple_rule['PortRange'] = rule['PortRange']
            simple_rule['IpProtocol'] = rule['IpProtocol']
            simple_rule['Policy'] = rule['Policy']
            if rule['Priority'] == 1:
                simple_rule['Priority'] = 'high'
            elif rule['Priority'] > 100:
                simple_rule['Priority'] = 'low'
            else:
                simple_rule['Priority'] = 'medium'
            simple_rules.append(simple_rule)
    simple_instance['rules'] = simple_rules

# 获取ECS配置
def getAliECSConfig(tag , access_config):
    # 创建AcsClient实例
    client = AcsClient(access_config['access_key'], access_config['access_key_secret'], access_config['region'])
    request = DescribeInstancesRequest.DescribeInstancesRequest()
    request.set_Tags([tag])
    request.set_PageSize(10)
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    print("ECS:%s"%responseStr)
    instanceList = responseStr["Instances"]["Instance"]
    simple_instances = []
    #print(instanceList)
    for instance in instanceList:
        simple_instance = {}
        # 获取云主机基本配置信息
        simple_instance['InstanceNetworkType'] = instance['InstanceNetworkType']
        if simple_instance['InstanceNetworkType'] != 'vpc':
            print("Can not migrate the instance for the unsupported network type! This scripts only support vpc network!")
            sys.exit(1)
        simple_instance['InstanceId'] = instance['InstanceId']
        simple_instance['ImageId'] = instance['ImageId']
        simple_instance['HostName'] = instance['HostName']
        simple_instance['Cpu'] = instance['Cpu']
        simple_instance['Memory'] = instance['Memory']
        simple_instance['PrivateIP'] = instance['VpcAttributes']['PrivateIpAddress']['IpAddress'][0]
        # 获取磁盘信息
        getDiskInfo(simple_instance, client)
        # 获取VPC详细信息
        simple_instance['VpcId'] = instance['VpcAttributes']['VpcId']
        getVpcInfo(simple_instance, client)
        # 获取子网信息
        simple_instance['VSwitchId'] = instance['VpcAttributes']['VSwitchId']
        getSubnetInfo(simple_instance, client)
        # 获取外网信息
        eip = {}
        public_ips = instance['PublicIpAddress']['IpAddress']
        eip_info = instance['EipAddress']
        if len(public_ips) > 0:
            eip['PublicIP'] = instance['PublicIpAddress']['IpAddress'][0]
            eip['InternetChargeType'] = instance['InternetChargeType']
            eip['InternetMaxBandwidthOut'] = instance['InternetMaxBandwidthOut']
        elif eip_info['IpAddress'] != '':
            eip['PublicIP'] = eip_info['IpAddress']
            eip['InternetChargeType'] = eip_info['InternetChargeType']
            eip['InternetMaxBandwidthOut'] = eip_info['Bandwidth']
        else :
            eip['PublicIP'] = ''
            eip['InternetChargeType'] = ''
            eip['InternetMaxBandwidthOut'] = ''
        simple_instance['eip'] = eip
        # 获取安全组信息
        simple_instance['SecurityGroupIds'] = instance['SecurityGroupIds']['SecurityGroupId']
        getSecurityGroup(simple_instance, client)
        simple_instances.append(simple_instance)
    return simple_instances

# 补充listener 详情
def get_listener_detail(client, listener, slb_id):
    protocol = listener['protocol']
    if protocol == 'udp':
        request = DescribeLoadBalancerUDPListenerAttributeRequest.DescribeLoadBalancerUDPListenerAttributeRequest()
        request.set_LoadBalancerId(slb_id)
        request.set_ListenerPort(listener['port'])
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        listener['method'] = responseStr['Scheduler']
        #print("udp listener: %s"%responseStr)
        if 'VServerGroupId' in responseStr:
            listener['vg'] = responseStr['VServerGroupId']
        elif 'BackendServerPort' in responseStr:
            listener['back_port'] = responseStr['BackendServerPort']
    elif protocol == 'http':
        request = DescribeLoadBalancerHTTPListenerAttributeRequest.DescribeLoadBalancerHTTPListenerAttributeRequest()
        request.set_LoadBalancerId(slb_id)
        request.set_ListenerPort(listener['port'])
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        listener['method'] = responseStr['Scheduler']
        if 'VServerGroupId' in responseStr:
            listener['vg'] = responseStr['VServerGroupId']
        elif 'BackendServerPort' in responseStr:
            listener['back_port'] = responseStr['BackendServerPort']
        #print("http listener attribute: %s"%responseStr)
    elif protocol == 'https':
        request = DescribeLoadBalancerHTTPSListenerAttributeRequest.DescribeLoadBalancerHTTPSListenerAttributeRequest()
        request.set_LoadBalancerId(slb_id)
        request.set_ListenerPort(listener['port'])
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        listener['method'] = responseStr['Scheduler']
        if 'VServerGroupId' in responseStr:
            listener['vg'] = responseStr['VServerGroupId']
        elif 'BackendServerPort' in responseStr:
            listener['back_port'] = responseStr['BackendServerPort']
    else:
        listener['protocol'] = 'tcp'
        request = DescribeLoadBalancerTCPListenerAttributeRequest.DescribeLoadBalancerTCPListenerAttributeRequest()
        request.set_LoadBalancerId(slb_id)
        request.set_ListenerPort(listener['port'])
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        #print("tcp listener attribute:%s"%responseStr)
        listener['method'] = responseStr['Scheduler']
        if 'VServerGroupId' in responseStr:
            listener['vg'] = responseStr['VServerGroupId']
        elif 'BackendServerPort' in responseStr:
            listener['back_port'] = responseStr['BackendServerPort']

def get_vserver_group(listener, client, slb_id):
    vgroup_id = listener['vg']
    request = DescribeVServerGroupAttributeRequest.DescribeVServerGroupAttributeRequest()
    request.set_VServerGroupId(vgroup_id)
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    backend_servers = []
    for server in responseStr['BackendServers']['BackendServer']:
        backend_server = {}
        backend_server['server_id'] = server['ServerId']
        backend_server['port'] = server['Port']
        backend_servers.append(backend_server)
    return backend_servers


# 获取SLB配置
def get_slb_config(tag, access_config):
    client = AcsClient(access_config['access_key'], access_config['access_key_secret'], access_config['region'])
    request = DescribeLoadBalancersRequest.DescribeLoadBalancersRequest()
    request.set_Tags([tag])
    response = client.do_action_with_exception(request)
    responseStr = json.loads(response)
    #print("SLB overview %s :"%responseStr)
    slb_list = responseStr['LoadBalancers']['LoadBalancer']
    ulb_list = []
    for slb in slb_list:
        slb_config = {}
        slb_id = slb['LoadBalancerId']
        request = DescribeLoadBalancerAttributeRequest.DescribeLoadBalancerAttributeRequest()
        request.set_LoadBalancerId(slb_id)
        response = client.do_action_with_exception(request)
        responseStr = json.loads(response)
        #print("SLB Attribute:%s"%responseStr)
        # slb基本信息
        slb_config['lb_name'] = responseStr['LoadBalancerName']
        slb_config['address_type'] = responseStr['AddressType']
        slb_config['bandwidth'] = responseStr['Bandwidth']

        # slb监听实例
        listener_list = []
        for listen_info in responseStr['ListenerPortsAndProtocol']['ListenerPortAndProtocol']:
            listener = {}
            listener['name'] = listen_info['Description']
            listener['protocol'] = listen_info['ListenerProtocol']
            listener['port'] = listen_info['ListenerPort']
            #print("listen_info:%s"%listen_info)
            # 填充负载均衡算法
            get_listener_detail(client, listener, slb_id)
            # slb绑定后端实例
            # get the backend servers from the vServerGroup first
            if 'vg' in listener:
                listener['rs'] = get_vserver_group(listener, client, slb_id)
            else:
                # get the backend servers from the default Server Group
                backend_servers = []
                for server in responseStr['BackendServers']['BackendServer']:
                    backend_server = {'server_id': server['ServerId'], 'port': listener['back_port']}
                    backend_servers.append(backend_server)
                listener['rs'] = backend_servers
            listener_list.append(listener)
            #print("listener list:%s"%listener_list)
        slb_config['listeners'] = listener_list
        ulb_list.append(slb_config)
    return ulb_list
    #print("ULB list: %s"%ulb_list)


if __name__ == "__main__":
    cf = configparser.ConfigParser()
    cf.read("./config.ini", encoding = 'utf-8')
    ali_config = {"access_key": cf['ali-cloud']['access_key'],
                  "access_key_secret": cf['ali-cloud']['access_key_secret'],
                  "region": cf['ali-cloud']['region']}
    tag = {'Key': cf['ali-cloud']['tag_key'], 'Value': cf['ali-cloud']['tag_value']}
    get_slb_config(tag, ali_config)
