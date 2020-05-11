import json
import boto3
import os
import logging
import itertools
import time
# from netaddr import IPNetwork
from botocore.exceptions import ClientError
from botocore.waiter import WaiterModel
from botocore.waiter import create_waiter_with_client

# Files Imported
from account_access import *
from waiters import *


# [GLOBAL VARIABLES]

role = ''
accepter_vpc_id = ''
requester_vpc_id = ''
requester_accounts = ''
requester_region = ''
accepter_vpc_id = ''
accepter_account = ''
accepter_region = ''
comp_hub_account = ''
comp_hub_region = ''
slack_channel = ''
slack_url = ''


# -------------------------------------------------------------------------------

# [CREATE LOGGER OBJECTS]

logger = logging.getLogger('simple_example')
logger.setLevel(logging.DEBUG)

# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

# create formatter
formatter = logging.Formatter('%(levelname)s - %(asctime)s - %(message)s')

# add formatter to ch
ch.setFormatter(formatter)

# add ch to logger
logger.addHandler(ch)


def lambda_handler(event, context):

    print(event)

    global accepter_vpc_id
    global accepter_account
    global accepter_region
    global requester_vpc_id
    global requester_account
    global requester_region
    global role
    global comp_hub_account
    global comp_hub_region
    global slack_channel
    global slack_url

    # Parameters received from lambda event from Lamda Test Event

    role = event['role']
    accepter_vpc_id = event['accepter_vpc_id']
    accepter_account = event['accepter_account']
    accepter_region = event['accepter_region']
    requester_vpc_id = event['requester_vpc_id']
    requester_account = event['requester_account']
    requester_region = event['requester_region']
    comp_hub_account = event['comp_hub_account']
    comp_hub_region = event['comp_hub_region']
    slack_channel = event['slack_channel']
    slack_url = event['slack_url']

    requester_session = create_session(requester_account, role, requester_region)
    accepter_session = create_session(accepter_account, role, accepter_region)
    comp_hub_session = create_session(comp_hub_account, role, comp_hub_region)

    ec2_r = requester_session.client('ec2')
    ec2_a = accepter_session.client('ec2')

    sns_ch = comp_hub_session.client('sns')

    vpc_r = Vpc()
    vpc_a = Vpc()

    cidr = Cidr()

    # ---------------------------------------------------------------------------

    # Describe Accepter VPC

    vpc_a.describe_vpcs(ec2_a, accepter_vpc_id)
    tags_a = vpc_a.tags
    cidr_block_a = vpc_a.cidr_block_associations

    # ---------------------------------------------------------------------------

    # Describe Requester VPCs

    vpc_r.describe_vpcs(ec2_r, requester_vpc_id)
    tags_r = vpc_r.tags
    cidr_block_r = vpc_r.cidr_block_associations

    # ---------------------------------------------------------------------------

    # ---------------------------------------------------------------------------

    # [DESCRIBE ACCEPTER AND REQUESTER VPC ROUTE TABLES]

    vpc_a.describe_route_tables(ec2_a, accepter_vpc_id)
    routes_a = vpc_a.routes
    rte_tbl_id_a = vpc_a.rte_tbl_id

    vpc_r.describe_route_tables(ec2_r, requester_vpc_id)
    routes_r = vpc_r.routes
    rte_tbl_id_r = vpc_r.rte_tbl_id

    # ---------------------------------------------------------------------------

    # Create VPC Peer Connection

    try:
        vpc_r.create_vpc_peer_connection(
            ec2_r, requester_vpc_id, accepter_vpc_id, accepter_account, accepter_region)
        peer_connection_id = vpc_r.peer_connection_id

        # raise ClientError('VpcPeeringConnectionAlreadyExists')

    except ClientError as err:
        print(err)

        if err.response['Error']['Code'] == 'VpcPeeringConnectionAlreadyExists':
            vpc_r.describe_peer_connections(ec2_t, requester_vpc_id, accepter_vpc_id)

            vpc_peering_connections = vpc.vpc_peering_connections

            for vpc_peering in vpc_peering_connections:
                accepter_vpc_id = vpc_peering['AccepterVpcInfo']['VpcId']
                requester_vpc_id = vpc_peering['RequesterVpcInfo']['VpcId']
                peer_connection_id = vpc_peering['VpcPeeringConnectionId']
                acc_owner_id = vpc_peering['AccepterVpcInfo']['OwnerId']
                req_owner_id = vpc_peering['RequesterVpcInfo']['OwnerId']
                acc_cidr_set = vpc_peering['AccepterVpcInfo']['CidrBlockSet']
                req_cidr_set = vpc_peering['RequesterVpcInfo']['CidrBlockSet']
                vpc_peer_tags = vpc_peering['Tags']

                acc_cidr_list = cidr.create_cidr_list(acc_cidr_set)
                req_cidr_list = cidr.create_cidr_list(req_cidr_set)

                print(f'VPC Peering Connection Already Exists')
                print(f'Peering Connection ID: {peer_connection_id}')

                # ---------------------------------------------------------------

                # [CHECKING ACCEPTER ROUTE TABLE]

                print(f'Checking Accepter VPC Route Table Routes')
                vpc_a.confirm_route_tbl_cidrs(routes_a, req_cidr_list,
                                              rte_tbl_id_a, ec2_a, peer_connection_id)

                # ---------------------------------------------------------------

                # [CHECKING REQUESTER ROUTE TABLE ROUTES]

                print(f'Checking Requester VPC Route Table Routes')
                vpc_r.confirm_route_tbl_cidrs(routes_r, acc_cidr_list,
                                              rte_tbl_id_r, ec2_r, peer_connection_id)

    # -----------------------------------------------------------------------

    # Create VPC Peer Connection Tags for Receiver and Accepter VPCs

    vpc_r.construct_tag_name(tags_a, tags_r, ec2_r, peer_connection_id,
                             requester_account, requester_account)
    vpc_a.construct_tag_name(tags_a, tags_r, ec2_a, peer_connection_id,
                             requester_account, accepter_account)

    # ---------------------------------------------------------------------------

    # time.sleep(20)

    vpc_a.accept_peer_connection(ec2_a, peer_connection_id)

    # ---------------------------------------------------------------------------

    # [ACCEPTER ROUTE TABLES]

    req_cidr_list = cidr.create_cidr_list(cidr_block_r)
    vpc_a.confirm_route_tbl_cidrs(routes_a, req_cidr_list, rte_tbl_id_a, ec2_a, peer_connection_id)
    # vpc_a.create_vpc_route(ec2_a, cidr_block_r, rte_tbl_id_a, peer_connection_id)

    # vpc_a.route_table_output(rte_tbl_id_a, routes_a)
    # ---------------------------------------------------------------

    # [REQUESTER ROUTE TABLES]

    acc_cidr_list = cidr.create_cidr_list(cidr_block_a)
    vpc_r.confirm_route_tbl_cidrs(routes_r, acc_cidr_list, rte_tbl_id_r, ec2_r, peer_connection_id)
    # vpc_r.create_vpc_route(ec2_r, cidr_block_a, rte_tbl_id_r, peer_connection_id)

    # vpc_r.route_table_output(rte_tbl_id_r, routes_r)

    # ---------------------------------------------------------------------------

    # [PUBLISH SLACK MESSAGE]

    slack_message = (f"""
        VPC PEERING COMPLETE. \n
            Accepter Account: {accepter_account}\n
                Accepter VPC: {accepter_vpc_id}
            Requester Account: {requester_account}\n
                Requester VPC: {requester_vpc_id}
            VPC Peering ID: {peer_connection_id}"""
                     )

    print('Sending message to slack channel')
    print(slack_message)
    # publish_sns_message(sns_ch, slack_message, slack_url , slack_channel)


class Vpc(object):

    def __init__(self):
        self.cidr_block_associations = None
        self.tags = None
        self.vpc_owner_id = None
        self.rte_tbl_id = None
        self.routes = None
        self.peer_connection_id = None

    def describe_vpc_peer(self, client, requester_vpc_id, accepter_vpc_id):
        vpc_peer = client.describe_vpc_peering_connections(
            Filters=[
                {
                    'Name': 'requester-vpc-info.vpc-id',
                    'Values': [requester_vpc_id]
                },
                {
                    'Name': 'accepter-vpc-info.vpc-id',
                    'Values': [accepter_vpc_id]
                }
            ]
        )
        self.vpc_peering_connections = vpc_peer['VpcPeeringConnections']
        self.vpc_peer_tags = [tag['Tags'] for tag in self.vpc_peering_connections]

    def describe_vpcs(self, client, vpc_id):
        vpcs = client.describe_vpcs(
            VpcIds=[vpc_id]
        )
        self.cidr_block_associations = vpcs['Vpcs'][0]['CidrBlockAssociationSet']
        self.tags = vpcs['Vpcs'][0]['Tags']
        self.vpc_owner_id = vpcs['Vpcs'][0]['OwnerId']

    def describe_route_tables(self, client, vpc_id):
        route_tables = client.describe_route_tables(
            Filters=[
                {
                    'Name': 'vpc-id',
                    'Values': [vpc_id]
                }
            ]
        )

        self.rte_tbl_id = route_tables['RouteTables'][0]['RouteTableId']
        self.routes = route_tables['RouteTables'][0]['Routes']

    def create_vpc_route(self, client, cidr, rte_tbl_id, peer_connection):

        # destination_cidrs = []

        # for dest_cidr in dest_cidrs:
        #     cidr = dest_cidr['CidrBlock']
        #     destination_cidrs.append(cidr)

        try:
            new_route = client.create_route(
                DestinationCidrBlock=cidr,
                RouteTableId=rte_tbl_id,
                VpcPeeringConnectionId=peer_connection
            )
            print(f'New Route Created for {peer_connection} in Route Table {rte_tbl_id}')

        except ClientError as e:
            if e == 'RouteLimitExceeded':
                logger.exception(f'Route Limit for {rte_tbl_id} has been reached')

    def create_vpc_peer_connection(self, client, req_vpc_id, acc_vpc_id, acc_owner_id, accepter_region):
        peer_connection = client.create_vpc_peering_connection(
            PeerOwnerId=acc_owner_id,
            PeerVpcId=acc_vpc_id,
            VpcId=req_vpc_id,
            PeerRegion=accepter_region

        )
        print(peer_connection)
        self.peer_connection_id = peer_connection['VpcPeeringConnection']['VpcPeeringConnectionId']

        print(f'VPC PEERING CONNECTION: {self.peer_connection_id} CREATED')

        # print('Calling Waiter...')
        self.get_waiter(client, self.peer_connection_id)
        # self.create_vpc_peering_waiter(self.peer_connection_id, client, peering_waiter, peering_config)

    def get_waiter(self, client, peer_connection_id):
        waiter = client.get_waiter('vpc_peering_connection_exists')
        waiter.wait(
            VpcPeeringConnectionIds=[peer_connection_id]
        )

    def accept_peer_connection(self, client, peer_connection_id):
        accept_peer = client.accept_vpc_peering_connection(
            VpcPeeringConnectionId=peer_connection_id
        )
        print(f'VPC PEERING CONNECTION: {peer_connection_id} ACCEPTED')

    def construct_tag_name(self, tags_a, tags_r, client, peer_connection_id, vpc_owner_id, target_account):
        a_vpc_name = []
        r_vpc_name = []

        try:
            # a_vpc_name = []
            for tag_a in tags_a:
                key = tag_a['Key']
                value = tag_a['Value']
                if key == 'Name':
                    a_vpc_name.append(value)
        except IndexError as e:
            logger.error(e)

        try:
            for tag_r in tags_r:
                key = tag_r['Key']
                value = tag_r['Value']
                if key == 'Name':
                    r_vpc_name.append(value)
        except IndexError as e:
            logger.error(e)

        if vpc_owner_id == target_account:
            tag_name = f'{r_vpc_name[0]}-->{a_vpc_name[0]}'
        elif vpc_owner_id != target_account:
            tag_name = f'{a_vpc_name[0]}-->{r_vpc_name[0]}'

        if a_vpc_name[0] != '':
            if r_vpc_name[0] != '':
                self.create_tag(client, peer_connection_id, tag_name)
                print(
                    f'Tag Name: {tag_name} for Peering Connection: {peer_connection_id} has been Created')

        else:
            logger.info('No VPC Name Tag. Peering Connection Tags will not be Created')

        return tag_name

    def create_tag(self, client, resource_id, resource_name):
        new_tag = client.create_tags(
            Resources=[resource_id],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': resource_name
                }
            ]
        )

    def delete_route(self, client, destination_cidr, rte_tbl_id):
        client.delete_route(
            DestinationCidrBlock=destination_cidr,
            RouteTableId=rte_tbl_id
        )

    def confirm_route_tbl_cidrs(self, routes, cidr_list, rte_tbl_id, client, peer_connection_id):
        peer_con_ids = []
        destination_cidrs = []
        d_cidr_to_delete = []

        for route in routes:
            try:
                destination_cidr = route['DestinationCidrBlock']
                peer_con_id = route['VpcPeeringConnectionId']
                state = route['State']

                peer_con_ids.append(peer_con_id)
                destination_cidrs.append(destination_cidr)

                # print(f'Destination Cidr: {destination_cidr}')
                # print(f'Peer Con Id: {peer_con_id}')
                # print(f'Peering Connection: {peer_connection_id}')

                if destination_cidr not in cidr_list:
                    if peer_connection_id == peer_con_id:
                        d_cidr_to_delete.append(destination_cidr)

                elif destination_cidr in cidr_list:
                    if state == 'blackhole':
                        d_cidr_to_delete.append(destination_cidr)
                        print(f'Route for Destination Cidr: {destination_cidr} is a blackhole')

            except KeyError as e:
                logger.error(e)
                continue

        if d_cidr_to_delete != []:
            for cidr in d_cidr_to_delete:
                logger.info(
                    f'Peering Connection: {peer_connection_id} Route with Cidr: {d_cidr_to_delete} will be Deleted')
                self.delete_route(client, cidr, rte_tbl_id)
                logger.info(
                    f'Route for Peering Connection: {peer_connection_id} with Destination Cidr: {cidr} has been deleted')

        print(cidr_list)
        for cidr in cidr_list:
            if cidr not in destination_cidrs:
                self.create_vpc_route(client, cidr, rte_tbl_id, peer_connection_id)
                logger.info(
                    f'Peer Connection Route has been Created for {peer_connection_id} and CIDR: {cidr}')
            else:
                logger.info(f'Routes are Compliant')


class Cidr(object):
    def __init__(self):
        self.cidr_block_associations = None
        self.cidr_list = None

    def create_cidr_list(self, cidr_set):

        self.cidr_list = []
        for cidr_s in cidr_set:
            cidr = cidr_s['CidrBlock']
            self.cidr_list.append(cidr)
        return self.cidr_list

    # def  check_for_overlapping_cidr(req_cidr_list, acc_cidr_list):
    #     for a_cidr, r_cidr in acc_cidr_list, req_cidr_list:
    #         acc_cidr = IPNetwork(a_cidr)
    #         req_cidr = IPNetwork(r_cidr)

    #         if acc_cidr in or == req_cidr:
    #             print(f'')

        # for cidrs in cidr_list:
        #     ap_cidr = IPNetwork(cidrs[0])
        #     vpc_cidr = IPNetwork(cidrs[1])

        #     if vpc_cidr in ap_cidr:
        #         print('VPC CIDR is part of Allowed Prefixes')
        #     else:
        #         print('VPC CIDR needs to be added to Allowed Prefixes')


def publish_sns_message(client, slack_message, slack_url, slack_channel):
    sns_message = client.publish(
        TopicArn=topicArn,
        Message=slack_message,
        MessageStructure='string',
        MessageAttributes={
            'channel': {
                'DataType': 'String',
                'StringValue': slack_channel

            },
            'webhook': {
                'DataType': 'String',
                'StringValue': slack_url

            }
        }
    )
