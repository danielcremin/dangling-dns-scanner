# Add the Slackbot's OAuth token to AWS Secret Manager

resource "aws_secretsmanager_secret" "slackbot_token_secret" {
  name        = var.slackbot_token_secret_name
  description = "Slackbot token secret name within Secrets Manager."
}

resource "aws_secretsmanager_secret_version" "slackbot_token_secret_version" {
  secret_id     = aws_secretsmanager_secret.slackbot_token_secret.id
  secret_string = var.slackbot_token_secret
}