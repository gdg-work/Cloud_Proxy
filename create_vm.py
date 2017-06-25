#!/usr/bin/env python3

import boto3
import botocore.client
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
    instanse_type : "t2.micro"
tor:
    port : 9050
proxy:
    socks:
        port: 9090
    http:
        port: 8080
"""


def msg(s_data):
    sys.stderr.write(s_data.__repr__() + "\n")
    sys.stderr.flush()
    return


def o_launch_VM(o_cfg):
    o_vm = None
    o_session = boto3.Session(profile_name=o_cfg['aws']['profile'])
    o_ec2 = o_session.client('ec2')
    if o_ec2:
        s_keyname = s_generate_key(o_ec2, o_cfg)
    return o_vm

def s_generate_key(o_ec2, o_cfg):
    """ Делает запрос на генерацию ключа, разбирает полученный ключ, 
    сохраняет его в файл в текущем каталоге (или в заданном? Имя файла? 
    Но файл точно нужен, для SSH потом)
    - имя файла можно сгенерировать уникальным (ami id + time, md5 -- для примеру)
    """
    s_keyName = "testaws"
    l_existing_keys = o_ec2.describe_key_pairs()['KeyPairs']
    # Delete an old key with this name
    for s_this_keydict in l_existing_keys:
        print(s_this_keydict)
        if s_this_keydict['KeyName'] == s_keyName:
            o_ec2.delete_key_pair(KeyName=s_keyName)
    # create a new keypair with a given name
    s_key = o_ec2.create_key_pair(KeyName=s_keyName)
    print('*DBG* generated key: ' + str(s_key))
    print(s_key)

    # write the secret key to a file
    s_fn = os.path.join(o_cfg['ssh']['keydir'], s_keyName + '.pem')
    with open(s_fn, "w") as f_out:
        f_out.write(s_key['KeyMaterial'])

    return s_keyName

def delete_key(o_cfg):
    """ Чистка -- удаление ключа из AWS """


def fo_readConfig(ls_args):
    o_config = None
    o_parser = ap.ArgumentParser(description="Make an ephermal VM on Amazon EC2 for vpn, proxy, etc")
    o_parser.add_argument('-c', '--config', help="Configuration file (YAML)", required=False)
    o_parser.add_argument('-r', '--region', help="Region (AWS datacenter)", required=False)
    o_parser.add_argument('-p', '--profile', help='AWS profile (from AWS config files', required=False)
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
            msg("File {} not found, using default configuration".format(s_cfg_filename))

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
