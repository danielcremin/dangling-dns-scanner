import boto3
from botocore.exceptions import ClientError
import ipaddress
import requests
import logging
import os
from helper_functions import HelperFunctions

# Set up a basic Python ERROR logger

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger()


class DanglingDNSChecker:

    def __init__(self):

        self.aws_ip_range_url = os.environ['aws_ip_ranges_url']

        # Instantiate EC2 & Route53 clients

        self.ec2_client = boto3.client('ec2')
        self.route53_client = boto3.client('route53')

        # Populate the AWS IP ranges variable with IP prefixes

        self.aws_ip_ranges = self.get_aws_ip_ranges()

        # Create a Helper Functions object

        self.helper_functions = HelperFunctions()

        # Slackbot details

        self.slackbot_token_secret_name = os.environ['slackbot_token_secret_name']
        self.slackbot_token_region = os.environ['slackbot_token_region']
        self.slack_channel = os.environ['slack_channel_name']

    def get_aws_ip_ranges(self) -> dict:

        """Returns the AWS IP ranges with associated services

           :return: dict: IP ranges as JSON"""

        try:
            r = requests.get(self.aws_ip_range_url)
            r.raise_for_status()
            return r.json()

        except requests.exceptions.RequestException as e:
            logger.error('[Error] - Failed to fetch IP ranges JSON file - Error: - {}'.format(e))

    def check_ip_in_aws_range(self, ip_address) -> str or None:

        """Checks if a given IP address is in the AWS IP range

        :param ip_address: to check
        :param aws_ip_ranges: JSON dictionary with IP ranges
        :return: str or None, matched prefix or None"""

        for prefix in self.aws_ip_ranges['prefixes']:
            network = ipaddress.ip_network(prefix['ip_prefix'])

            if ipaddress.ip_address(ip_address) in network:
                return True

        return False

    def check_ip_aws_region(self, ip_address) -> str:

        """Checks an IP against the AWS IP range to determine the region,

           :param: ip_address:
           :return: str: region name or Unknown"""

        for prefix in self.aws_ip_ranges['prefixes']:
            network = ipaddress.ip_network(prefix['ip_prefix'])

            if ipaddress.ip_address(ip_address) in network:
                return prefix['region']

        return 'Unknown'

    def get_hosted_zones(self) -> dict:

        """Returns a list of Route53 hosted zones for the account

           :return: list: of hosted zones"""

        try:
            return self.route53_client.list_hosted_zones()

        except ClientError as e:
            logger.error('[Error] - Failed to get list of hosted zones. Error: {}'.format(e))

    def get_a_records(self, hosted_zones) -> list:

        """Gets a list of A records from each of the hosted zones found

           :param hosted_zones: a list of hosted zones for the account
           :return: list: of Route53 A records"""

        a_records = []

        for hosted_zone in hosted_zones['HostedZones']:
            hosted_zone_id = hosted_zone['Id']

            try:
                records = self.route53_client.list_resource_record_sets(HostedZoneId=hosted_zone_id)

            except ClientError as e:
                logger.error('[Error] - Failed to get list of A records. Error: {}'.format(e))

        for record in records['ResourceRecordSets']:
            if record['Type'] == 'A':
                a_records.append(record)

        return a_records

    def get_enabled_regions(self) -> list:

        """Gets a list of enabled regions for the current AWS account

           :return: list: of enabled regions"""

        regions = None
        enabled_regions = []

        try:
            regions = self.ec2_client.describe_regions()
        except ClientError as e:
            logger.error('[Error] - Failed to get enabled regions. Error: {}'.format(e))

        for region in regions['Regions']:
            enabled_regions.append(region['RegionName'])

        return enabled_regions

    def get_elastic_ip_list(self, enabled_regions) -> list:

        """Iterates through all enabled regions appending elastic IPs to a list

           :param enabled_regions: for the given AWS account
           :return: list: of all elastic IP addresses"""

        elastic_ip_list = []

        for region in enabled_regions:

            ec2_client = boto3.client('ec2', region_name=region)

            try:
                elastic_ips = ec2_client.describe_addresses()
            except ClientError as e:
                logger.error('[Error] - Failed to get elastic IPs for region: {}. Error: {}'.format(region, e))

            for elastic_ip in elastic_ips['Addresses']:
                try:
                    elastic_ip_list.append(elastic_ip['PublicIp'])
                except KeyError:  # Account for no elastic IP addresses
                    pass

        return elastic_ip_list

    def get_public_ip_list(self, enabled_regions) -> list:

        """Iterates through all enabled regions appending EC2 public IPs to a list

           :param enabled_regions: for the given AWS account
           :return: list: of all EC2 public IP addresses"""

        public_ip_list = []

        for region in enabled_regions:

            ec2_client = boto3.client('ec2', region_name=region)

            try:
                r = ec2_client.describe_instances()
            except ClientError as e:
                logger.error('[Error] - Failed to get public IP addresses for region: {}. Error: {}'.format(region, e))

            for reservation in r['Reservations']:
                for instance in reservation['Instances']:
                    try:
                        public_ip_address = instance['PublicIpAddress']
                        public_ip_list.append(public_ip_address)
                    except KeyError:  # Account for no public IP addresses
                        pass

        return public_ip_list

    def a_record_ip_check(self, a_records, elastic_ip_list, public_ip_list) -> list:

        """Creates a list of dictionaries with details of a given A record,
           checks if the IP is owned by AWS and if there is an elastic IP or
           EC2 public IP match for the IP within the current AWS account.

           :param a_records: a list of the Route53 A records
           :param elastic_ip_list: from all regions in the account
           :param public_ip_list: from all regions in the account
           :return: list: of record_check which includes the owner and match status for elastic/public IPs"""

        a_record_check_results = []

        for record in a_records:

            record_check = {'a_record': 'parked.example.com', 'ip_address': '0.0.0.0', 'aws_owned': False,
                            'elastic_ip_match': False, 'public_ip_match': False}

            ip_address = record['ResourceRecords'][0]['Value']
            record_check.update({'a_record': record['Name'], 'ip_address': ip_address})

            if self.check_ip_in_aws_range(ip_address):
                record_check.update({'aws_owned': True})

            if ip_address in elastic_ip_list:
                record_check.update({'elastic_ip_match': True})

            if ip_address in public_ip_list:
                record_check.update({'public_ip_match': True})

            a_record_check_results.append(record_check)

        return a_record_check_results

    def find_dangling_a_record(self, a_record_check_results):

        """Checks the items in the a_record_check_results to determine if there
           is an IP address that is owned by AWS, mapped to a Route53 A record
           and does not have a corresponding elastic IP or EC2 public IP address
           which may suggest a dangling DNS record is present.

           :param: a_record_check_results: list of details about a given A record
           :return: (Print results for now)"""

        for result in a_record_check_results:

            if result['aws_owned']:
                if not result['elastic_ip_match'] and not result['public_ip_match']:

                    logger.critical('[Potential dangling DNS record] - {}'.format(result))

                    return {'dangling_record': True,
                            'msg': '[Potential dangling DNS record] - {}'.format(result)}

                else:
                    logger.info('[Matching elastic or public IP in region: {}] - {}'.format(
                        self.check_ip_aws_region(result['ip_address']), result))

                    return {'dangling_record': False,
                            'msg': '[Matching elastic or public IP in region: {}] - {}'.format(
                                self.check_ip_aws_region(result['ip_address']), result)}
            else:
                logger.info('[A record IP address is not owned by AWS] - {}'.format(result))

                return {'dangling_record': False,
                        'msg': '[A record IP address is not owned by AWS] - {}'.format(result)}

    def notify_dangling_record(self, slack_message) -> bool:

        """Sends a message to a notification Slack channel if a potential dangling DNS
           record is found.

           :param: slack_message: to send
           :return: bool: True/False on a successfully sent message"""

        slackbot_token = self.helper_functions.sm_retrieve_secret(self.slackbot_token_secret_name,
                                                                  self.slackbot_token_region)

        return self.helper_functions.send_slack_msg(slackbot_token, self.slack_channel, slack_message)

    def app(self, event):

        if event:

            hosted_zones = self.get_hosted_zones()
            a_records = self.get_a_records(hosted_zones)

            enabled_regions = self.get_enabled_regions()

            elastic_ip_list = self.get_elastic_ip_list(enabled_regions)
            public_ip_list = self.get_public_ip_list(enabled_regions)

            a_record_check_results = self.a_record_ip_check(a_records, elastic_ip_list, public_ip_list)

            dangling_dns_response = self.find_dangling_a_record(a_record_check_results)

            if dangling_dns_response['dangling_record']:

                slack_r = self.notify_dangling_record(dangling_dns_response['msg'])
                if slack_r:
                    logger.info(
                        'Notified Slack channel: {} of potential dangling DNS record.'.format(self.slack_channel))

            elif not dangling_dns_response['dangling_record']:
                logger.info('No dangling DNS records discovered for this account. Check response {}'.format(
                    dangling_dns_response['msg']))


def lambda_handler(event, context):
    DanglingDNSChecker().app(event)
