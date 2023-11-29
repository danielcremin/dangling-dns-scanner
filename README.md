# Dangling DNS Scanner

A Route53 DNS record scanner to identify potential dangling DNS A records in your AWS account.

## Introduction

When an AWS Elastic IP (EIP) or Public IP (commonly linked to EC2 instances) is released back to AWS' IP pool, the lingering presence of a corresponding Route 53 record tied to that IP address poses a potential security risk. In such a scenario, a malicious actor could seize the released IP address, thereby gaining effective control over the associated domain or subdomain.

Furthermore, CNAME records are also susceptible to this type of attack. For example, if a S3 bucket associated with a CNAME is released - an attacker can claim the bucket and host their own code/assets for malicious intent.

This Lambda-based tool scans your Route 53 **A records**, cross-referencing the associated IP address with all Elastic and Public IPs for the given account. If a dangling A record is found (i.e. a record that is owned by AWS, but does not have a corresponding Elastic or Public IP in the account) - a Slack message is sent to a dedicated notification channel to notify the Security/Network team.

**Note: At present this tool only audits Route53 A Records.**

## Features

- Deploys to AWS Lambda, via Terraform to your AWS.
- Retrieve all A Records, from all Route53 hosted zones in a given AWS account.
- Compares A Records associated IP addresses with Elastic and Public IP addresses in the account to identify dangling records.
- Send a Slack message to a dedicated channel when a dangling DNS record is identified.

## Example

- A sample Slack message for an identified dangling DNS A record:

<img src='https://github.com/danielcremin/dangling-dns-scanner/assets/84750315/7f9bb91b-80e0-4c8a-9d1b-8eb728b6093f' width='600'>

## Getting Started

To get started, simply clone the repository.

### Prerequisites

- Access to an AWS account, with the relevant permissions required to deploy the Terraform code.
- Terraform installation on your deployment method of choice.
- Access to Slack instance to deploy and generate required OAuth tokens for messages.

### Prerequisites - Slackbot Configuration

- Create a Slack bot user (app) that will be capable of posting messages to a defined Slack channel -> [Slack Apps](https://api.slack.com/apps)
- The bot will need *chat:write* permissions at the very least to publish to a channel it has been invited to.
- The **Bot User OAuth Token** will the **slackbot_token_secret** you will need in your **variables.auto.tfvars** below.
- Install your bot to your desired Workspace.

### Installation

* Clone the repository locally:
```
git clone https://github.com/danielcremin/dangling-dns-scanner.git
```
- Create your own **variables.auto.tfvars** file with the following variables, adding the required values to each:

  - See *dangling-dns-scanner/terraform/vars.tf* for variable descriptions.

```
aws_access_key = ""
aws_secret_key = ""
aws_region     = ""
aws_account_id = ""
project_owner  = ""

lambda_python_runtime_version = "python3.9"

aws_ip_ranges_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"

slackbot_token_secret_name = ""
slackbot_token_region      = ""
slack_channel_name         = ""
slackbot_token_secret      = ""
```

- Create your own Lambda layer zip file (optional, but recommended):

  - For simplicity, I have zipped the required Lambda layers for this script (requests v2.28.2 and slack-sdk v3.26.0). However, as a security best practice - you should always audit code and packages pulled directly from the internet. If you have an internal repository manager you should pull a mirrored/scanned version from there or pull manually and scan before zipping.
 
- Run the following commands (updating versions where required) to create your Lambda layer zip file:
  - Requests has been pinned to v2.28.2 to prevent urllib3 error with AWS Lambda.

```mkdir python
   cd python
   pip3 install requests==v2.28.2
   pip3 install slack-sdk==v3.26.0
   cd ..
   zip -r dangling_dns_scanner_layer.zip .
```

- At this point, you can consider your scan frequency. By default, this script will run every hour via EventBridge trigger. To change the frequency, update the following to your desired frequency:

  - *dangling-dns-scanner/terraform/lambda.tf -> resource "aws_cloudwatch_event_rule" "DanglingDNSScanner_EventBridge"*

```
schedule_expression = "rate(1 hour)"
schedule_expression = "rate(12 hours)"
schedule_expression = "rate(24 hours)"
```

- Run your Terraform plan, you should expect to see 16 resources to add:

```
terraform plan

Plan: 16 to add, 0 to change, 0 to destroy.
```

- Terraform your Terraform apply if you are happy with the additions:
```
terraform apply --auto-approve
```
- You're done, the script should run at the scheduled interval and alert the Slack channel to any dangling A records.

```
Apply complete! Resources: 16 added, 0 changed, 0 destroyed.
```

## Caveats

- This script is intended to be best effort and may contain bugs (I am not a Software Engineer). If you encounter a bug, please open a pull request. Additionally, if you see an opportunity for improvement - please let me know.

- If you run a Terraform apply/destroy more than once, consider that AWS Secrets Manager will schedule a secret for deletion when a Terraform destroy runs. Therefore, you should update the name of the secret in your **variables.auto.tfvars** file before re-running an apply. Otherwise, Terraform will timeout with a secret already exists and is scheduled for deletion error. Alternatively, comment out the secret creation and keep a static secret in Secrets Manager - updating your IAM Terraform accordingly.

## Future Work

- Extend the script to check for CNAME dangling records connected to other AWS services such as S3 and Elastic Beanstalk.
- Add optional remediation functionality that would automatically update records to remove offending IPs or CNAMEs.
- Improve the processing time and account for large numbers of Route53 records in a hosted zone(s).

## Additional Links

- [Terraform documentation on schedule frequency](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/scheduler_schedule)

## Author

- [Daniel Cremin](https://dcremin.com)

## License

- [GNU General Public License v3.0](https://github.com/danielcremin/dangling-dns-checker/blob/main/LICENSE)