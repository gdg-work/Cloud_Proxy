#!/usr/bin/env python3

import boto3
import botocore as bc
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
    profile : vagrantLopa
    datacenter : eu-west-1
    ami : "ami-060cde69"
    instance_type : "t2.micro"
tor:
    port : 9050
proxy:
    socks:
        port: 9090
    http:
        port: 8080
"""
SECURITY_GROUP_NAME='aws_proxy'


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
    # d_resp = o_ec2_res.describe_security_groups(GroupNames=[SECURITY_GROUP_NAME])
    for o_sg in o_ec2_res.security_groups.all():
        if o_sg.group_name == SECURITY_GROUP_NAME:
            b_groupFound = True
            s_grpId = o_sg.id
            break

    if b_groupFound:
        msg('*DBG* o_assign_security_group: target SG found')
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


def o_create_instance(o_ec2res, o_cfg, d_keyPair, s_sg_id):
    ld_blockdevs = [{'DeviceName': '/dev/xvdh',
                     'Ebs': {'DeleteOnTermination': True,
                             'VolumeSize': 20, 'VolumeType': 'standard'}}]
    s_ami_id = 'ami-060cde69'
    # s_def_instanceType = 't2.micro'
    s_inst_type = o_cfg['aws']['instance_type']
    # s_region = o_cfg['aws']['region']
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
                    )

    except Exception as e:
        msg("*ERR* Cannot create an instance, error below:")
        msg(str(e))
        o_instance = None
    return o_instance


def b_launch_dryrun(o_ec2, s_id):
    """ Test run of an instance, return True if success, False otherwise """
    try:
        o_ec2.start_instances(InstanceIds=[s_id], DryRun=True)
    except bc.ClientError as e:
        if 'DryRunOperation' not in str(e):
            raise
    return False


def o_launch_VM(o_cfg):
    o_vm = None
    o_ec2_res = None
    o_session = boto3.Session(profile_name=o_cfg['aws']['profile'])
    o_ec2 = o_session.client('ec2')
    if o_ec2:
        d_keyPair = o_generate_key(o_ec2, o_cfg)
        o_ec2_res = o_session.resource('ec2', use_ssl=True)
    if o_ec2_res:
        s_sg_id = s_create_security_group(o_ec2_res)
        lo_instances = o_create_instance(o_ec2_res, o_cfg, d_keyPair, s_sg_id)
    for o_instance in lo_instances:
        msg("*DBG* CREATE successful, instance information:")
        msg(str(o_instance))
        msg('Launched an instance with ID "{}" and IP {}'.format(
            o_instance.instance_id, o_instance.public_ip_address))
    return o_vm


def o_generate_key(o_ec2, o_cfg):
    """ Делает запрос на генерацию ключа, разбирает полученный ключ,
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
    print('*DBG* generated key: ' + str(d_key))

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
                    msg("Error parsing configuration: {}".format(ex))
                    msg('Will use default')
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
    o_new_vm = o_launch_VM(o_cfg)
    exit()
