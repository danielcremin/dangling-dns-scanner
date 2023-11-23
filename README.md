# Dangling DNS Scanner

A Lambda based Route53 record scanner to identify potential dangling DNS A records in your AWS account.

## Introduction

When an AWS Elastic IP (EIP) or public IP (commonly linked to an EC2 instance) is released back into AWS' IP pool, the presence of a corresponding Route 53 record tied to that IP address poses a potential security risk. In such a scenario, a malicious actor could seize the released IP address, thereby gaining effective control over the associated domain or subdomain.

Therefore, is imperative to routinely audit your Route53 records are ensure that their are no 'dangling DNS records' that are pointing to IP addresses no longer associated/owned by the AWS account.

This Lambda-based tool scans your Route 53 A records, cross-referencing the associated IP addresses with your Elastic and Public IPs across all enabled regions for the given account. If a dangling record is detected, a Slack message is sent to a notification channel to notify the Security/Network team.

**Note: At present this tool only audits Route53 A Records, future scope may include CNAME records.**


## Features

Deploy to Lambda, via Terraform or CloudFormation to your AWS account - update the scan interval to your desired frequency.

- Retrieve all A records, from all Route53 hosted zones in given AWS account.
- Compare A record IP addresses with AWS Elastic and Public IP addresses, identifying any broken links.
- Send a Slack message to a dedication channel when a dangling DNS record is identified.

## Getting Started

### Prerequisites

-
-

### Installation

-
-

### Author

[Daniel Cremin](https://dcremin.com)

### License

[GNU General Public License v3.0](https://github.com/danielcremin/dangling-dns-checker/blob/main/LICENSE)
