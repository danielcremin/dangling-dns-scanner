import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import logging

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger()


class HelperFunctions:

    # A collection of helper functions for AWS related boto3/Lambda use

    def client_create(self, client_type, region) -> object:

        """Creates a boto3 client for the given AWS service

           :param: client_type: desired client
           :param: region: region to create the client in
           :return: object: the boto3 client"""

        try:
            return boto3.client(
                service_name=client_type,
                region_name=region
            )
        except ClientError as e:

            logger.error('[Error] - Failed to create boto3 client for {}. Error: {}'.format(client_type, e))

    def sm_retrieve_secret(self, secret_name, region) -> str:

        """Retrieves a secret from AWS Secret Manager

           :param: secret_name: of the secret to retrieve
           :param: region: that the secret is stored in
           :return: the secret"""

        sm_client = self.client_create('secretsmanager', region)

        try:
            r = sm_client.get_secret_value(SecretId=secret_name)

            secret = r.get('SecretString')

            return secret

        except NoCredentialsError:
            logger.error('[Error] - Valid credentials unavailable to retrieve secret.')

        except ClientError as e:
            logger.error('[Client Error] - {}'.format(e))

    def send_slack_msg(self, slackbot_token, slack_channel, slack_message_blocks) -> bool:

        """Sends a message to a specific Slack channel using the Slack SDK library

           :param: slackbot_token: the token of the Slackbot the message is sent on behalf of
           :param: slack_channel: the channel to send the message to
           :param: slack_message: the message to send
           :return: bool: True/False based on the Slack sending outcome"""

        client = WebClient(token=slackbot_token)

        try:
            response = client.chat_postMessage(
                channel=slack_channel,
                text="Message cannot be rendered",
                blocks=slack_message_blocks
            )
            if response['ok']:
                logger.info('Slack message sent to channel: {}'.format(slack_channel))
                return True

            else:
                logger.error('[Error], response is: {}'.format(response))
                return False

        except SlackApiError as e:
            logger.error('[SlackApiError] - {}'.format(e.response['error']))
            return False

    def slack_msg_blocks(self, dangling_dns_response, aws_account_id) -> list:

        """Formats & populates the Slack message block to send to Slack

           :param: dangling_dns_response: dict: of a potential dangling DNS record
           :return: list: Slack message block"""

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: Potential Dangling DNS Record Found :rotating_light:",
                    "emoji": True
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*A Record:* {}".format(dangling_dns_response['a_record'])
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*IP Address:* {}".format(dangling_dns_response['ip_address'])
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*AWS Owned IP:* {}".format(dangling_dns_response['aws_owned'])
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Matching Elastic IP in Account:* {}".format(dangling_dns_response['elastic_ip_match'])
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": "*Matching Public IP in Account:* {}".format(dangling_dns_response['public_ip_match'])
                }
            },
            {
                "type": "divider"
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "*AWS Account ID:* {} | <https://github.com/danielcremin/dangling-dns-scanner|Scanner "
                                "Github Documentation>".format(aws_account_id)
                    }
                ]
            }
        ]

        return blocks
