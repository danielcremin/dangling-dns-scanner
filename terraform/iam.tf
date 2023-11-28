# Lambda - Trust Policy

data "aws_iam_policy_document" "DanglingDNSScanner_TrustPolicy" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# Lambda - Basic Execution policy

resource "aws_iam_policy" "DanglingDNSScanner_BasicExecutionPolicy" {
  name        = "DanglingDNSScanner_BasicExecutionPolicy"
  description = "This policy allows Lambda to create & put logs into a CloudWatch log group."
  policy      = data.aws_iam_policy_document.DanglingDNSScanner_BasicExecutionPolicy_Document.json
  tags = {
    owner = var.project_owner
  }
}

data "aws_iam_policy_document" "DanglingDNSScanner_BasicExecutionPolicy_Document" {

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup"]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:/aws/lambda/DanglingDNSScanner:*"]
  }
}

# Lambda - Retrieve secrets from Secrets Manager

resource "aws_iam_policy" "DanglingDNSScanner_RetrieveSecretManagerSecret" {
  name        = "DanglingDNSScanner_RetrieveSecretManagerSecret"
  description = "This policy allows the DanglingDNSScanner to retrieve a secret from Secrets Manager."
  policy      = data.aws_iam_policy_document.DanglingDNSScanner_RetrieveSecretManagerSecret_Document.json
  tags = {
    owner = var.project_owner
  }
}

data "aws_iam_policy_document" "DanglingDNSScanner_RetrieveSecretManagerSecret_Document" {

  statement {
    effect    = "Allow"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:ListSecrets"]
    resources = [aws_secretsmanager_secret.slackbot_token_secret.id]
  }
}

# Lambda - Query Route53 hosted zones

resource "aws_iam_policy" "DanglingDNSScanner_Route53GetHostedZones" {
  name        = "DanglingDNSScanner_Route53GetHostedZones"
  description = "This policy allows the DanglingDNSScanner to List & Get Route53 hosted zone."
  policy      = data.aws_iam_policy_document.DanglingDNSScanner_Route53GetHostedZones_Document.json
  tags = {
    owner = var.project_owner
  }
}

data "aws_iam_policy_document" "DanglingDNSScanner_Route53GetHostedZones_Document" {

  statement {
    effect = "Allow"
    actions = ["route53:GetHostedZone", "route53:ListHostedZones",
    "route53:ListHostedZonesByName", "route53:ListResourceRecordSets"]
    resources = ["*"]
  }
}

# Lambda - Query Elastic IP (EIP), EC2 public IP addresses and describe regions

resource "aws_iam_policy" "DanglingDNSScanner_EC2Permissions" {
  name        = "DanglingDNSScanner_EC2Permissions"
  description = "This policy allows the DanglingDNSScanner to get account EIPs, EC2 public IPs and list enabled regions."
  policy      = data.aws_iam_policy_document.DanglingDNSScanner_EC2Permissions_Document.json
  tags = {
    owner = var.project_owner
  }
}

data "aws_iam_policy_document" "DanglingDNSScanner_EC2Permissions_Document" {

  statement {
    effect    = "Allow"
    actions   = ["ec2:DescribeRegions", "ec2:DescribeAddresses", "ec2:DescribeInstances"]
    resources = ["*"]
  }
}