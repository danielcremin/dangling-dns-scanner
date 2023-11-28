# Create IAM role and attach Trust policy

resource "aws_iam_role" "DanglingDNSScanner_IAM_Role" {
  name               = "DanglingDNSScanner_IAM_Role"
  assume_role_policy = data.aws_iam_policy_document.DanglingDNSScanner_TrustPolicy.json
  tags = {
    owner = var.project_owner
  }
}

# Attach additional IAM policies

resource "aws_iam_role_policy_attachment" "DanglingDNSScanner_BasicExecutionPolicy" {
  role       = aws_iam_role.DanglingDNSScanner_IAM_Role.name
  policy_arn = aws_iam_policy.DanglingDNSScanner_BasicExecutionPolicy.arn
}

resource "aws_iam_role_policy_attachment" "DanglingDNSScanner_RetrieveSecretManagerSecret" {
  role       = aws_iam_role.DanglingDNSScanner_IAM_Role.name
  policy_arn = aws_iam_policy.DanglingDNSScanner_RetrieveSecretManagerSecret.arn
}

resource "aws_iam_role_policy_attachment" "DanglingDNSScanner_Route53GetHostedZones" {
  role       = aws_iam_role.DanglingDNSScanner_IAM_Role.name
  policy_arn = aws_iam_policy.DanglingDNSScanner_Route53GetHostedZones.arn
}

resource "aws_iam_role_policy_attachment" "DanglingDNSScanner_EC2Permissions" {
  role       = aws_iam_role.DanglingDNSScanner_IAM_Role.name
  policy_arn = aws_iam_policy.DanglingDNSScanner_EC2Permissions.arn
}

# Zip Python code into main.zip

data "archive_file" "DanglingDNSScanner" {
  type        = "zip"
  source_dir  = "../src"
  output_path = "${path.module}/DanglingDNSScanner/main.zip"
}

# DanglingDNSScanner - Lambda layer configuration

resource "aws_lambda_layer_version" "python_layer" {
  layer_name          = "dangling_dns_scanner_layer"
  filename            = "${path.module}/DanglingDNSScanner/dangling_dns_scanner_layer.zip"
  description         = "Additional packages required for execution."
  compatible_runtimes = [var.lambda_python_runtime_version]
  source_code_hash    = filebase64("${path.module}/DanglingDNSScanner/dangling_dns_scanner_layer.zip")
}

# DanglingDNSScanner - Lambda configuration

resource "aws_lambda_function" "DanglingDNSScanner" {
  filename      = "${path.module}/DanglingDNSScanner/main.zip"
  layers        = [aws_lambda_layer_version.python_layer.arn]
  function_name = "DanglingDNSScanner"
  description   = "This function scans Route53 for dangling DNS A records."
  role          = aws_iam_role.DanglingDNSScanner_IAM_Role.arn
  handler       = "main.lambda_handler"
  runtime       = var.lambda_python_runtime_version
  memory_size   = 1024
  timeout       = 600

  ephemeral_storage {
    size = 1024
  }

  environment {
    variables = {

      aws_ip_ranges_url          = var.aws_ip_ranges_url
      slackbot_token_secret_name = var.slackbot_token_secret_name
      slackbot_token_region      = var.slackbot_token_region
      slack_channel_name         = var.slack_channel_name
    }
  }

  tags = {
    owner = var.project_owner
  }
}

# Create EventBridge cron rule to run the Lambda scanner every hour

resource "aws_cloudwatch_event_rule" "DanglingDNSScanner_EventBridge" {
  name                = "DanglingDNSScanner_EventBridge"
  description         = "This EventBridge triggers DanglingDNSScanner Lambda to run each hour."
  schedule_expression = "rate(1 hour)"
  depends_on          = [aws_lambda_function.DanglingDNSScanner]
  tags = {
    owner = var.project_owner
  }
}

# Attach EventBridge cron rule

resource "aws_cloudwatch_event_target" "DanglingDNSScanner_EventBridgeTarget" {
  target_id = aws_lambda_function.DanglingDNSScanner.function_name
  arn       = aws_lambda_function.DanglingDNSScanner.arn
  rule      = aws_cloudwatch_event_rule.DanglingDNSScanner_EventBridge.name
}

# Allow EventBridge to trigger Lambda

resource "aws_lambda_permission" "DanglingDNSScanner_EventBridgeTrigger" {
  statement_id  = "AllowEventBridgeTriggerLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.DanglingDNSScanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.DanglingDNSScanner_EventBridge.arn
  depends_on    = [aws_cloudwatch_event_rule.DanglingDNSScanner_EventBridge]
}