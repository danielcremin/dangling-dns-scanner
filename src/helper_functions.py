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
                service_name = client_type,
                region_name = region
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

    def send_slack_msg(self, slackbot_token, slack_channel, slack_message) -> bool:

        """Sends a message to a specific Slack channel using the Slack SDK library

           :param: slackbot_token: the token of the Slackbot the message is sent on behalf of
           :param: slack_channel: the channel to send the message to
           :param: slack_message: the message to send
           :return: bool: True/False based on the Slack sending outcome"""

        client = WebClient(token=slackbot_token)

        try:
            response = client.chat_postMessage(
                channel=slack_channel,
                text=slack_message
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
