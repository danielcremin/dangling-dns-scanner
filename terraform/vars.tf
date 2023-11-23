# Global project variables

variable "aws_access_key" {
  description = "Access key required to deploy terraform."
  type        = string
}

variable "aws_secret_key" {
  description = "Secret key required to deploy terraform."
  type        = string
}

variable "aws_region" {
  description = "AWS region where the application will be deployed to."
  type        = string
}

variable "aws_account_id" {
  description = "The account ID of the AWS account"
  type        = string
}

variable "project_owner" {
  description = "The owner of the project."
  type        = string
}

# Lambda related variables

variable "lambda_python_runtime_version" {
  description = "The Python runtime version"
  type        = string
}

variable "slackbot_token_secret_name" {
  description = "The Slackbot's token secret name in Secrets Manager."
  type        = string
}

variable "slackbot_token_region" {
  description = "The region the Slackbot token secret is stored in."
  type        = string
}

variable "slack_channel_name" {
  description = "The name of the Slack channel to send notifications to."
  type        = string
}