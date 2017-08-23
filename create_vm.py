#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import boto3
# import botocore as bc
import argparse as ap
import yaml
# import json
import sys
import os


# -- CONSTANTS --
DEFAULT_CFG = """
ssh:
    keydir: "."
aws:
    ami : "ami-060cde69"
    profile : vagrantLopa
    instance_type : "t2.micro"
    frontend:
        machine_name: Test-Proxy-Frontend
        datacenter : eu-west-1
    backend:
        machine_name: Test-Proxy-Backend
        datacenter : eu-central-1
tor:
    port : 9050
proxy:
    socks:
        port: 9090
    http:
        port: 8080
"""
SECURITY_GROUP_NAME = 'aws_proxy'


def msg(s_data):
    sys.stderr.write(s_data.__repr__() + "\n")
    sys.stderr.flush()
    return


def s_create_security_group(o_ec2_res):
    """Checks if a security group named aws_proxy exists, if yes, does nothing,
    if no, creates this security group. Allow ports 22, 8000-9000 and ICMP
    from Internet
    """
    # check if we have our security group available
    b_groupFound = False
    # d_resp = o_ec2_res.describe_security_groups(
    #                GroupNames=[SECURITY_GROUP_NAME])
    for o_sg in o_ec2_res.security_groups.all():
        if o_sg.group_name == SECURITY_GROUP_NAME:
            b_groupFound = True
            s_grpId = o_sg.id
            break

    if b_groupFound:
        msg('*INFO* o_assign_security_group: target SG found')
        pass
    else:
        # create a security group
        o_sg = o_ec2_res.create_security_group(
            Description="SG for a temporary proxy server",
            GroupName=SECURITY_GROUP_NAME,
            )
        msg('*DBG* created security group with ID: {}'.format(o_sg.id))
        if o_sg:
            s_grpId = o_sg.id
            s_resp = o_sg.authorize_ingress(
                IpPermissions=[
                    {
                        'IpProtocol': 'icmp',
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                        'FromPort': -1,
                        'ToPort': -1,
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 8000,
                        'ToPort': 9000,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                    },
                    ]
                )
            msg('*DBG* SG modified, response is ' + str(s_resp))
    return s_grpId


def o_create_instance_internal(o_ec2res, d_instance_data):
    """Create an AWS EC2 instance. Parameters:
    1) EC2 resource object
    2) Dictionary with instance data (see below)
    Returns: instance object.

    d_instance_data = {'blockdevs': [], 'ami_id': '', 'inst_type': '',
                       'region': '', 'keyname': '', 'sg_id': '',
                       'vm_name': ""}
    """
    l_tagsSpec = [{'ResourceType': 'instance',
                   'Tags': [{'Key': 'Name',
                             'Value': d_instance_data['vm_name']},
                            {'Key': 'AutoCreated', 'Value': 'Yes'},
                            {'Key': 'PartOfProxy', 'Value': 'Yes'}
                            ]}]
    try:
        l_instance = o_ec2res.create_instances(
                        InstanceType=d_instance_data['inst_type'],
                        ImageId=d_instance_data['ami_id'],
                        MinCount=1,
                        MaxCount=1,
                        KeyName=d_instance_data['keyname'],
                        BlockDeviceMappings=d_instance_data['blockdevs'],
                        SecurityGroupIds=[d_instance_data['sg_id']],
                        # DryRun = True,
                        TagSpecifications=l_tagsSpec,
                    )
        if len(l_instance) == 1:
            o_instance = l_instance.pop()

    except Exception as e:
        msg("*ERR* o_create_instance_internal:" +
            "Cannot create an instance, error below:")
        msg(str(e))
        o_instance = None
    return o_instance


def o_create_instance2(o_ec2res, o_cfg, d_keyPair, s_sg_id):
    l_instances = []
    ld_blockdevs = [{'DeviceName': '/dev/xvdh',
                     'Ebs': {'DeleteOnTermination': True,
                             'VolumeSize': 20, 'VolumeType': 'standard'}}]
    # s_ami_id = o_cfg['aws']['ami']
    # s_inst_type = o_cfg['aws']['instance_type']
    # s_region = o_cfg['aws']['region']
    for o_vm_data in (o_cfg['aws']['backend'], o_cfg['aws']['frontend']):
        try:
            d_data = {'blockdevs': ld_blockdevs,
                      'ami_id': o_cfg['aws']['ami'],
                      'inst_type': o_cfg['aws']['instance_type'],
                      'region': o_vm_data['datacenter'],
                      'vm_name': o_vm_data['machine_name'],
                      'sg_id': s_sg_id,
                      'keyname': d_keyPair['KeyName'],
                      }
            o_inst = o_create_instance_internal(o_ec2res, d_data)
            l_instances.append(o_inst)
        except Exception as e:
            msg("*ERR* o_create_instance: Can't create instance, error below:")
            msg(str(e))
    return l_instances


def o_create_instance(o_ec2res, o_cfg, d_keyPair, s_sg_id):
    ld_blockdevs = [{'DeviceName': '/dev/xvdh',
                     'Ebs': {'DeleteOnTermination': True,
                             'VolumeSize': 20, 'VolumeType': 'standard'}}]
    s_ami_id = o_cfg['aws']['ami']
    # s_def_instanceType = 't2.micro'
    s_inst_type = o_cfg['aws']['instance_type']
    # s_region = o_cfg['aws']['region']
    if 'machine_name' in o_cfg['aws']:
        l_tagsSpec = [{'ResourceType': 'instance',
                      'Tags': [
                          {'Key': 'Name',
                           'Value': o_cfg['aws']['machine_name']},
                          {'Key': 'AutoCreated', 'Value': 'Yes'}
                          ]}]
    else:
        l_tagsSpec = []
    o_instance = None
    try:
        o_instance = o_ec2res.create_instances(
                        InstanceType=s_inst_type,
                        ImageId=s_ami_id,
                        MinCount=1,
                        MaxCount=1,
                        KeyName=d_keyPair['KeyName'],
                        BlockDeviceMappings=ld_blockdevs,
                        SecurityGroupIds=[s_sg_id],
                        # DryRun = True,
                        TagSpecifications=l_tagsSpec,
                    )

    except Exception as e:
        msg("*ERR* Cannot create an instance, error below:")
        msg(str(e))
        o_instance = None
    return o_instance


def o_search_my_instance_id(o_ec2, o_cfg):
    """Поиск instance id в заданном регионе, ID образа и некоторым тегам
       (имени и ключу AutoCreated)
    """
    s_id = ''
    return s_id


def s_search_ami_id(o_ec2, o_cfg):
    """Поиск инстанса Ubuntu LTS в заданном в конфигурации регионе"""
    s_ami_id = "ami-060cde69"
    l_filters = [
            {'Name': 'image-type', 'Values': ['machine']},
            {'Name': 'architecture', 'Values': ['x86_64']},
            {'Name': 'name', 'Values': ['ubuntu/images/*trusty*']},
            # {'Name': 'root-device-type', 'Values': ['ebs']},
            {'Name': 'is-public', 'Values': ['true']},
            # {'Name': '', 'Values': []},
            ]
    d_response = o_ec2.describe_images(
            ExecutableUsers=['all'],
            Filters=l_filters,
            )
    print(d_response)
    for d_ami_description in d_response['Images']:
        pass

    raise
    return s_ami_id


def launch_VMs(o_cfg):
    o_ec2_res = None
    o_session = boto3.Session(profile_name=o_cfg['aws']['profile'])
    o_ec2 = o_session.client('ec2')
    if o_ec2:
        d_keyPair = o_generate_key(o_ec2, o_cfg)
        o_ec2_res = o_session.resource('ec2', use_ssl=True)
        # o_cfg['aws']['ami'] = s_search_ami_id(o_ec2, o_cfg)
    if o_ec2_res:
        s_sg_id = s_create_security_group(o_ec2_res)
        lo_instances = o_create_instance2(o_ec2_res, o_cfg, d_keyPair, s_sg_id)
    if len(lo_instances) == 2:
        for o_instance in lo_instances:
            msg("*DBG* CREATE successful, instance information:")
            msg(str(o_instance))
            msg('*INF* Launched an instance with ID "{}" and IP {}'.format(
                o_instance.instance_id, o_instance.public_ip_address))
            # We know that there should be only one instance
            o_instance.wait_until_running(
                Filters=[
                    {
                        'Name': 'instance-id',
                        'Values': [str(o_instance.instance_id)]   # list
                    }])
    return


def o_generate_key(o_ec2, o_cfg):
    """Делает запрос на генерацию ключа, разбирает полученный ключ,
    сохраняет его в файл в текущем каталоге (или в заданном? Имя файла?
    Но файл точно нужен, для SSH потом)
    - имя файла можно сгенерировать уникальным (ami id + time,
    md5 -- для примеру)
    """
    s_keyName = "testaws"
    l_existing_keys = o_ec2.describe_key_pairs()['KeyPairs']
    # Delete an old key with this name
    for s_this_keydict in l_existing_keys:
        print(s_this_keydict)
        if s_this_keydict['KeyName'] == s_keyName:
            o_ec2.delete_key_pair(KeyName=s_keyName)
    # create a new keypair with a given name
    d_key = o_ec2.create_key_pair(KeyName=s_keyName)
    # msg('*DBG* generated key: ' + str(d_key))

    # write the secret key to a file
    s_fn = os.path.join(o_cfg['ssh']['keydir'], s_keyName + '.pem')
    with open(s_fn, "w") as f_out:
        f_out.write(d_key['KeyMaterial'])
    return d_key


def fo_readConfig(ls_args):
    o_config = None
    o_parser = ap.ArgumentParser(
            description="Make an ephermal VM on AWS for vpn, proxy, etc")
    o_parser.add_argument('-c', '--config',
                          help="Configuration file (YAML)", required=False)
    o_parser.add_argument('-r', '--region',
                          help="Region (AWS datacenter)", required=False)
    o_parser.add_argument('-p', '--profile',
                          help='AWS profile (from AWS config files',
                          required=False)
    o_clidata = o_parser.parse_args()
    s_cfg_filename = o_clidata.config

    o_config = yaml.load(DEFAULT_CFG)
    if s_cfg_filename:
        try:
            with open(s_cfg_filename, "r") as f_in:
                try:
                    o_config = yaml.load(f_in)
                except yaml.YAMLError as ex:
                    msg("*ERR* Error parsing configuration: {}".format(ex))
                    msg('*CONT* Will use default')
        except FileNotFoundError:
            msg("File {} not found, using default configuration".format(
                s_cfg_filename))

    # replace some data from CLI arguments
    if o_clidata.region:
        o_config['aws']['datacenter'] = o_clidata.region
    if o_clidata.profile:
        o_config['aws']['profile'] = o_clidata.profile
    return o_config


if __name__ == "__main__":
    # read the configuration from a first file in CLI
    o_cfg = fo_readConfig(sys.argv)
    msg(o_cfg)
    launch_VMs(o_cfg)
    exit()
