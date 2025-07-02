# 创建Lambda层
resource "aws_lambda_layer_version" "push_to_teams_layer" {
  layer_name = "push-to-teams-layer"
  filename = "${path.module}/../../data/push-to-teams-layer.zip"
  compatible_runtimes = "python3.13"
  source_code_hash = filebase64sha256("${path.module}/../../data/push-to-teams-layer.zip")
}

# Lambda函数
resource "aws_lambda_function" "tasys_lambda_push_to_teams" {
  architectures = ["x86_64"]
  environment {
    variables = {
      "cloud_watch_url"       = "https:/xxxxxx"
      "messenger_webhook_url" = var.messenger_webhook_url
    }
  }

  ephemeral_storage {
    size = "512"
  }

  function_name = "aaa-${var.environment}-lambda-push-to-teams"
  handler       = "push_to_teams.lambda_handler"
  layers = [aws_lambda_layer_version.push_to_teams_layer.arn]

  logging_config {
    log_format = "Text"
    log_group  = "/aws/lambda/aaa-${var.environment}-lambda-push-to-teams"
  }

  memory_size   = "128"
  package_type  = "Zip"
  role          = var.lambda_role_arn
  runtime       = "python3.13"
  timeout       = "60"
  filename      = "${path.module}/../../data/aaa-lambda-push-to-teams.zip"

  tracing_config {
    mode = "PassThrough"
  }
}
