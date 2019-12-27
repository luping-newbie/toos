#!/usr/bin/env python
# coding=utf-8
'''This script are supposed to generate the final terraform file'''

import getAliConfig
import pandas as pd
import configparser
import sys

# 载入配置
cf = configparser.ConfigParser()
cf.read("./config.ini", encoding = 'utf-8')
terraform_tf = cf['terraform-setting']['tf_workspace'] + "main.tf"
public_key = cf['ucloud']['public_key']
private_key = cf['ucloud']['private_key']
project_id = cf['ucloud']['project_id']
region = cf['ucloud']['region']
az = cf['ucloud']['az']
root_password = cf['resource-setting']['root_password']
ali_config = {"access_key" : cf['ali-cloud']['access_key'],
            "access_key_secret" : cf['ali-cloud']['access_key_secret'],
            "region" : cf['ali-cloud']['region']}
tag = {'Key': cf['ali-cloud']['tag_key'], 'Value': cf['ali-cloud']['tag_value']}
# load the relationship between the private IP of ali-cloud and image ID of UCloud
cf.read("./ip_image_map.ini", encoding = 'utf-8')
ip_image_map = cf['ip-image-map']
# define a map to store relationship between private IP of ali-cloud and host terraform name of UCloud
ip_host_map = {}
# define a map to store relationship between ECS ID and private IP of ali-cloud
id_ip_map = {}

# 主机系统盘类别字典
host_system_disk_dict = {
    "cloud" : "cloud_ssd",
    "cloud_efficiency" : "cloud_ssd",
    "cloud_ssd" : "cloud_ssd",
    "cloud_essd" : "cloud_ssd",
    "local_hdd_pro" : "local_normal",
    "local_sdd_pro" : "local_ssd"
}
# 主机数据盘类别字典
host_data_disk_dict = {
    "cloud" : "local_normal",
    "cloud_efficiency" : "local_normal",
    "cloud_ssd" : "local_ssd",
    "cloud_essd" : "local_ssd",
    "local_hdd_pro" : "local_normal",
    "local_sdd_pro" : "local_ssd"
}
# 云盘磁盘类别字典
data_disk_dict = {
    "cloud" : "data_disk",
    "cloud_efficiency" : "data_disk",
    "cloud_ssd" : "ssd_data_disk",
    "cloud_essd" : "rssd_data_disk",
}
# rule 字典
rule_dict = {
}

# ulb method diction
ulb_method_dict = {
    "rr" : "roundrobin",
    "wrr" : "weight_roundrobin",
    "wlc" : "leastconn"
}

# template 定义
# provider模板
tp_provider = '''provider "ucloud"{{
    public_key = "{pubKey}"
    private_key = "{priKey}"
    project_id = "{project}"
    region = "{region}"
}}'''
# vpc模板
tp_vpc = '''resource "ucloud_vpc" "vpc"{{
    name = "{vpc_name}"
    cidr_blocks = ["{cidr_blocks}"]
}}'''

# subnet 模板
tp_subnet = '''resource "ucloud_subnet" "subnet"{{
    name = "{subnet_name}"
    cidr_block = "{cidr_block}"
    vpc_id = ucloud_vpc.vpc.id
}}'''

# 安全组模板
tp_sg = '''resource "ucloud_security_group" "{sg_name}"{{
    {rulelist}
}}'''

# rule 模板
tp_rule = '''    rules{{
            port_range = "{port_range}"
            protocol = "{protocol}"
            cidr_block = "{cidr_block}"
            policy = "{policy}"
            priority = "{priority}"
        }}'''

# 应用服务器模板
tp_host = '''resource "ucloud_instance" "{tf_host_name}" {{
    availability_zone = "{az}"
    image_id = "{image_id}"
    instance_type = "{instance_type}"
    boot_disk_size = {boot_disk_size}
    boot_disk_type = "{boot_disk_type}"
    {datadisk_str}
    vpc_id = ucloud_vpc.vpc.id
    subnet_id = ucloud_subnet.subnet.id
    security_group = ucloud_security_group.{firewall_name}.id
    root_password = "{root_password}"
    name = "{host_name}"
}}
'''
# Eip模板
tp_eip = '''resource "ucloud_eip" "{eip_name}"{{
    internet_type = "bgp"
    bandwidth = {bandwidth}
    charge_mode = "{charge_mode}"
    charge_type = "{charge_type}"
}}'''

# Eip 绑定到云主机的模板
tp_eip_instance = '''resource "ucloud_eip_association" "{eip_host_name}"{{
    resource_id = ucloud_instance.{host_name}.id
    eip_id = ucloud_eip.{eip_name}.id
}}'''
# eip bind to ulb
tp_eip_ulb = '''resource "ucloud_eip_association" "{eip_ulb_name}"{{
    resource_id = ucloud_lb.{ulb_name}.id
    eip_id = ucloud_eip.{eip_name}.id
}}'''

# UDisk创建模板
tp_udisk = '''resource "ucloud_disk" "{tf_disk_name}" {{
    availability_zone = "{az}"
    name = "{disk_name}"
    disk_size = {disk_size}
    disk_type = "{disk_type}"
}}'''

# UDisk绑定到云主机模板
tp_udisk_host = '''resource "ucloud_disk_attachment" "{disk_host_name}" {{
    availability_zone = "{az}"
    disk_id           = ucloud_disk.{disk_name}.id
    instance_id       = ucloud_instance.{host_name}.id
}}'''

# ULB模板
tp_ulb = '''resource "ucloud_lb" "{tf_ulb_name}" {{
    name = "{ulb_name}"
    internal = "{is_intranet}"
    vpc_id = ucloud_vpc.vpc.id
    subnet_id = ucloud_subnet.subnet.id
}}'''

# listener模板
tp_listener = '''resource "ucloud_lb_listener" "{tf_listener_name}" {{
    load_balancer_id = ucloud_lb.{ulb_name}.id
    protocol = "{protocol}"
    name = "{name}"
    port = "{port}"
    method = "{method}"
}}'''

# ulb-listener-attachment
tp_ulb_listener_host = '''resource "ucloud_lb_attachment" "{ulb_host_bind_name}" {{
    load_balancer_id = ucloud_lb.{ulb_name}.id
    listener_id      = ucloud_lb_listener.{listener_name}.id
    resource_id      = ucloud_instance.{host_name}.id
    port             = {port}
}}'''

# rule去重
def removeDuplicateRules(rules):
    dataframe_rules = pd.DataFrame(rules)
    distinct_rules_list = dataframe_rules.drop_duplicates(['PortRange', 'SourceCidrIp', 'IpProtocol'], keep='last').values\
        .tolist()
    return_rules = []
    for rule in distinct_rules_list:
        rule_dict = {}
        rule_dict['SourceCidrIp'] = rule[0]
        rule_dict['PortRange'] = rule[1]
        rule_dict['IpProtocol'] = rule[2]
        rule_dict['Policy'] = rule[3]
        rule_dict['Priority'] = rule[4]
        return_rules.append(rule_dict)
    return return_rules

# 生成terraform公用资源，如provider,vpc,subnet
def gen_tf_file_common(host, file):
    # 写provider
    file.writelines("# provider definition block \n")
    file.writelines(tp_provider.format(pubKey=public_key, priKey=private_key, project=project_id, region=region)
                    + "\n")
    # 写 vpc
    vpc_name = host['vpc']['vpc_name']
    if vpc_name == '':
        vpc_name = 'tf-vpc'
    vpc_cidr_str = str(host['vpc']['vpc_cidr_blocks'])
    file.writelines("# vpc definition block \n")
    file.writelines(tp_vpc.format(vpc_name=vpc_name, cidr_blocks=vpc_cidr_str) + "\n")

    # 写 subnet
    subnet_name = host['subnet']['subnet_name']
    if subnet_name == '':
        subnet_name = 'tf-subnet'
    file.write("# subnet definition block \n")
    file.writelines(tp_subnet.format(subnet_name=subnet_name, cidr_block=host['subnet']['subnet_cidr']) + "\n")

# 根据安全组id列表生成key
def gen_sg_key(sg_list):
    key = 'sg_'
    for sg_id in sg_list:
        key = key + sg_id[15:-1]
    return key
# 生成ecs terraform文件
def gen_tf_file_ecs_each(host, file, exist_firewalls, count):
    #print("Generating terraform file for each ecs%d!"%count)
    id_ip_map[host['InstanceId']] = host['PrivateIP']
    # 写 firewall
    #print(host['SecurityGroupIds'])
    sg_key = gen_sg_key(host['SecurityGroupIds'])
    # 如果该安全组列表对应的防火墙已经存在，则跳过
    if sg_key not in exist_firewalls:
        tp_rules = ''
        distinct_rules = removeDuplicateRules(host['rules'])
        for rule in distinct_rules:
            # print(rule)
            port_range = ''
            ports = rule['PortRange'].split("/")
            if ports[0] == ports[1]:
                port_range = ports[0]
            else:
                port_range = ports[0] + "-" + ports[1]
            if port_range == '-1':
                port_range = "1-65535"
            real_rule = tp_rule.format(port_range=port_range, protocol=rule['IpProtocol'].lower(),
                                       cidr_block=rule['SourceCidrIp'],
                                       policy=rule['Policy'].lower(), priority=rule['Priority'])
            tp_rules = tp_rules + "\n" + real_rule
        exist_firewalls.append(sg_key)
        file.writelines("# security group definition blocks for \n")
        file.writelines(tp_sg.format(sg_name = sg_key, rulelist=tp_rules) + "\n")
    # 写 instance
    cpu = host['Cpu']
    mem = host['Memory']
    ratio = mem/1024/cpu
    instanceType = ''
    if ratio == 1:
        instanceType = 'n-highcpu-' + str(cpu)
    elif ratio == 2:
        instanceType = 'n-basic-' + str(cpu)
    elif ratio == 4:
        instanceType = 'n-standard-' + str(cpu)
    elif ratio == 8:
        instanceType = 'n-highmem-' + str(cpu)
    else:
        instanceType = 'n-customized-' + str(cpu) + "-" + str(mem)
    bootdisk = {}
    disks = host['disks']
    for disk in disks:
        if disk['Type'] == 'system':
            bootdisk = disk
            disks.remove(disk)
    datadisk_str = ''
    if len(disks) != 0 :
        datadisk = disks[0]
        data_type = host_data_disk_dict[bootdisk['Category']] #host_data_disk_dict[datadisk['Category']]
        datadisk_str = '''data_disk_size = {disk_size}
    data_disk_type = "{disk_type}" '''.format(disk_size = datadisk['Size'], disk_type = data_type)
    host_name = "host_" + host['HostName'] + "_" + str(count)
    instance_name = host['HostName']
    private_ip = host['PrivateIP']
    image_id = ip_image_map[private_ip]
    tf_instance = tp_host.format(tf_host_name = host_name, az = az, image_id = image_id, instance_type = instanceType, boot_disk_size = bootdisk['Size'],
                   boot_disk_type = host_data_disk_dict[bootdisk['Category']], datadisk_str = datadisk_str,
                   firewall_name = sg_key, root_password = root_password, host_name = instance_name)
    ip_host_map[private_ip] = host_name
    file.writelines("# host definition block for %s \n"%host_name)
    file.writelines(tf_instance + "\n")
    # 写Udisk,第一个数据盘随云主机创建，第二个数据盘通过挂载云盘得方式创建，暂不支持三个及以上的数据盘创建。
    if len(disks) >= 2 :
        datadisk2 = disks[1]
        data_disk2_type = data_disk_dict[datadisk2['Category']]
        data_disk2_name = "udisk_" + datadisk2['DiskName'] + "_" + str(count)
        if data_disk2_name == '':
            data_disk2_name = 'tf-data-udisk'
        tf_data_disk = tp_udisk.format(tf_disk_name = data_disk2_name, az = az, disk_name = data_disk2_name,
                                       disk_size = datadisk2['Size'], disk_type = data_disk2_type)
        file.writelines("# disk definition block for %s \n"%host_name)
        file.writelines(tf_data_disk + "\n")
        # 写UDisk和host之间的绑定关系
        disk_host_name = "disk_host_bind_" + str(count)
        tf_udisk_host = tp_udisk_host.format(disk_host_name = disk_host_name, az = az, disk_name = data_disk2_name, host_name = host_name)
        file.writelines("# bind disk to host \n")
        file.writelines(tf_udisk_host + "\n")


    # 写 eip, 计费模式默认为按带宽，且按月
    if host['eip']['PublicIP'] != '':
        eip_name = "eip_" + host_name
        tf_eip = tp_eip.format(eip_name = eip_name, bandwidth = host['eip']['InternetMaxBandwidthOut'],
                  charge_mode = "bandwidth", charge_type = "month")
        file.writelines("# eip definition block for %s \n"%host_name)
        file.writelines(tf_eip + "\n")
        # 写eip和host的绑定关系
        eip_host_name = "eip_host_name_" + str(count)
        tf_eip_instance = tp_eip_instance.format(eip_host_name = eip_host_name, host_name = host_name, eip_name = eip_name)
        file.writelines("# bind eip to host \n")
        file.writelines(tf_eip_instance + "\n")

# 写入ulb
def  gen_tf_file_ulb(ulbs, file):
    print("------Generating  terraform file for ulb!------")
    count = 0
    for ulb in ulbs:
        # write ulb basic
        ulb_name = ulb['lb_name'] + "_" + str(count)
        is_intranet = 'false'
        if ulb['address_type'] == 'intranet':
            is_intranet = 'true'
        tf_ulb = tp_ulb.format(tf_ulb_name = ulb_name, ulb_name = ulb_name, is_intranet = is_intranet)
        file.writelines("# ulb definition block \n")
        file.writelines(tf_ulb + "\n")
        file.writelines("# listeners definition block \n")
        # write listener
        for listener in ulb['listeners']:
            listener_name = listener['name'] + "_" + str(count)
            tf_listener = tp_listener.format(tf_listener_name = listener_name, ulb_name = ulb_name,
                                             protocol = listener['protocol'], name = listener_name,
                                             port = listener['port'],method = ulb_method_dict[listener['method']])
            file.writelines(tf_listener + "\n")
            # bind listener, ulb, realservver together
            rs_count = 0
            for backend_server in listener['rs']:
                server_id = backend_server['server_id']
                #print(id_ip_map)
                private_ip = id_ip_map[server_id]
                host_name = ip_host_map[private_ip]
                ulb_host_bind_name = ulb_name + "_" + listener_name + "_host_" +  str(rs_count)
                back_port = backend_server['port']
                # if the ulb works in layer 4, back_port is the same as the listener_port
                if back_port == "" or listener['protocol'] == 'udp':
                    back_port = listener['port']
                tf_ulb_listener_host = tp_ulb_listener_host.format(ulb_host_bind_name = ulb_host_bind_name,
                                                                   ulb_name = ulb_name, listener_name = listener_name,
                                                                   host_name = host_name, port = back_port)
                file.writelines(tf_ulb_listener_host + "\n")
                rs_count = rs_count + 1
        # bind eip to ulb
        if is_intranet == 'false':
            bandwidth = ulb['bandwidth']/1024
            eip_name = "eip_" + ulb_name + "_" + str(count)
            tf_eip = tp_eip.format(eip_name = eip_name, bandwidth = bandwidth, charge_mode = "bandwidth",
                               charge_type = "month")
            file.writelines(tf_eip + "\n")
            eip_ulb_name =  "eip_ulb_" + ulb_name + "_" + str(count)
            tf_eip_ulb = tp_eip_ulb.format(eip_ulb_name = eip_ulb_name, ulb_name = ulb_name, eip_name = eip_name)
            file.writelines(tf_eip_ulb + "\n")
        count = count + 1



def gen_tf_file_main():
    file = open(terraform_tf, 'w+')
    hosts = getAliConfig.getAliECSConfig(tag, ali_config)
    print("gen_tf_file_main, hosts: %s"%hosts)
    # 写入terraform provider，vpc，subnet，这里认为一次迁移的架构都在同一个vpc的同一子网下
    gen_tf_file_common(hosts[0],file)
    # 写入 ecs
    exist_firewalls = []
    count = 0
    print("------Generating terraform file for ECS------")
    for host in hosts:
        gen_tf_file_ecs_each(host, file, exist_firewalls, count)
        count = count + 1
    # 写入ulb
    ulbs = getAliConfig.get_slb_config(tag, ali_config)
    print(ulbs)
    gen_tf_file_ulb(ulbs, file)

# 测试时调用
if __name__ == "__main__":
    if len(sys.argv) == 2:
        terraform_tf = sys.argv[1]
    #print(terraform_tf)
    gen_tf_file_main()
    print("The terraform file generated at location : %s" % terraform_tf)

