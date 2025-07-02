
| ID | Provider | Service | Description|
|-|-|-|-|
| aws-s3-no-public-access-with-acl | aws | s3 | S3 Bucket has an ACL defined which allows public access. |
| aws-s3-enable-bucket-logging | aws | s3 | S3 Bucket does not have logging enabled. |
| aws-rds-no-classic-resources | aws | rds | AWS Classic resource usage. |
| aws-elbv2-http-not-used | aws | elbv2 | Use of plain HTTP. |
| aws-elbv2-alb-not-public | aws | elbv2 | Load balancer is exposed to the internet. |
| aws-vpc-no-public-ingress-sgr | aws | vpc | An ingress security group rule allows traffic from /0. |
| aws-vpc-no-public-egress-sgr | aws | vpc | An egress security group rule allows traffic to /0. |
| aws-vpc-no-public-ingress-sg | aws | vpc | An inline ingress security group rule allows traffic from /0. |
| aws-vpc-no-public-egress-sg | aws | vpc | An inline egress security group rule allows traffic to /0. |
| aws-vpc-use-secure-tls-policy | aws | vpc | An outdated SSL policy is in use by a load balancer. |
| aws-rds-no-public-db-access | aws | rds | A database resource is marked as publicly accessible. |
| aws-autoscaling-no-public-ip | aws | autoscaling | A resource has a public IP address. |
| aws-ecs-no-plaintext-secrets | aws | ecs | Task definition defines sensitive environment variable(s). |
| aws-autoscaling-enable-at-rest-encryption | aws | autoscaling | Launch configuration with unencrypted block device. |
| aws-sqs-enable-queue-encryption | aws | sqs | Unencrypted SQS queue. |
| aws-sns-enable-topic-encryption | aws | sns | Unencrypted SNS topic. |
| aws-s3-enable-bucket-encryption | aws | s3 | Unencrypted S3 bucket. |
| aws-vpc-add-description-to-security-group | aws | vpc | Missing description for security group/security group rule. |
| aws-kms-auto-rotate-keys | aws | kms | A KMS key is not configured to auto-rotate. |
| aws-cloudfront-enforce-https | aws | cloudfront | CloudFront distribution allows unencrypted (HTTP) communications. |
| aws-cloudfront-use-secure-tls-policy | aws | cloudfront | CloudFront distribution uses outdated SSL/TLS protocols. |
| aws-msk-enable-in-transit-encryption | aws | msk | A MSK cluster allows unencrypted data in transit. |
| aws-ecr-enable-image-scans | aws | ecr | ECR repository has image scans disabled. |
| aws-kinesis-enable-in-transit-encryption | aws | kinesis | Kinesis stream is unencrypted. |
| aws-api-gateway-use-secure-tls-policy | aws | api-gateway | API Gateway domain name uses outdated SSL/TLS protocols. |
| aws-elastic-service-enable-domain-encryption | aws | elastic-service | Elasticsearch domain isn't encrypted at rest. |
| aws-elastic-search-enable-in-transit-encryption | aws | elastic-search | Elasticsearch domain uses plaintext traffic for node to node communication. |
| aws-elastic-search-enforce-https | aws | elastic-search | Elasticsearch doesn't enforce HTTPS traffic. |
| aws-elastic-search-use-secure-tls-policy | aws | elastic-search | Elasticsearch domain endpoint is using outdated TLS policy. |
| aws-elastic-search-encrypt-replication-group | aws | elastic-search | Unencrypted Elasticache Replication Group. |
| aws-elasticache-enable-in-transit-encryption | aws | elasticache | Elasticache Replication Group uses unencrypted traffic. |
| aws-iam-no-password-reuse | aws | iam | IAM Password policy should prevent password reuse. |
| aws-iam-set-max-password-age | aws | iam | IAM Password policy should have expiry less than or equal to 90 days. |
| aws-iam-set-minimum-password-length | aws | iam | IAM Password policy should have minimum password length of 14 or more characters. |
| aws-iam-require-symbols-in-passwords | aws | iam | IAM Password policy should have requirement for at least one symbol in the password. |
| aws-iam-require-numbers-in-passwords | aws | iam | IAM Password policy should have requirement for at least one number in the password. |
| aws-iam-require-lowercase-in-passwords | aws | iam | IAM Password policy should have requirement for at least one lowercase character. |
| aws-iam-require-uppercase-in-passwords | aws | iam | IAM Password policy should have requirement for at least one uppercase character. |
| aws-misc-no-exposing-plaintext-credentials | aws | misc | AWS provider has access credentials specified. |
| aws-cloudfront-enable-waf | aws | cloudfront | CloudFront distribution does not have a WAF in front. |
| aws-sqs-no-wildcards-in-policy-documents | aws | sqs | AWS SQS policy document has wildcard action statement. |
| aws-efs-enable-at-rest-encryption | aws | efs | EFS Encryption has not been enabled |
| aws-vpc-no-public-ingress | aws | vpc | An ingress Network ACL rule allows specific ports from /0. |
| aws-vpc-no-excessive-port-access | aws | vpc | An ingress Network ACL rule allows ALL ports. |
| aws-rds-encrypt-cluster-storage-data | aws | rds | There is no encryption specified or encryption is disabled on the RDS Cluster. |
| aws-rds-encrypt-instance-storage-data | aws | rds | RDS encryption has not been enabled at a DB Instance level. |
| aws-rds-enable-performance-insights | aws | rds | Encryption for RDS Performance Insights should be enabled. |
| aws-elastic-search-enable-domain-logging | aws | elastic-search | Domain logging should be enabled for Elastic Search domains |
| aws-lambda-restrict-source-arn | aws | lambda | Ensure that lambda function permission has a source arn specified |
| aws-athena-enable-at-rest-encryption | aws | athena | Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted |
| aws-athena-no-encryption-override | aws | athena | Athena workgroups should enforce configuration to prevent client disabling encryption |
| aws-api-gateway-enable-access-logging | aws | api-gateway | API Gateway stages for V1 and V2 should have access logging enabled |
| aws-ec2-no-secrets-in-user-data | aws | ec2 | User data for EC2 instances must not contain sensitive AWS keys |
| aws-cloudtrail-enable-all-regions | aws | cloudtrail | Cloudtrail should be enabled in all regions regardless of where your AWS resources are generally homed |
| aws-cloudtrail-enable-log-validation | aws | cloudtrail | Cloudtrail log validation should be enabled to prevent tampering of log data |
| aws-cloudtrail-enable-at-rest-encryption | aws | cloudtrail | Cloudtrail should be encrypted at rest to secure access to sensitive trail data |
| aws-eks-encrypt-secrets | aws | eks | EKS should have the encryption of secrets enabled |
| aws-eks-enable-control-plane-logging | aws | eks | EKS Clusters should have cluster control plane logging turned on |
| aws-eks-no-public-cluster-access-to-cidr | aws | eks | EKS cluster should not have open CIDR range for public access |
| aws-eks-no-public-cluster-access | aws | eks | EKS Clusters should have the public access disabled |
| aws-elastic-search-enable-logging | aws | elastic-search | AWS ES Domain should have logging enabled |
| aws-cloudfront-enable-logging | aws | cloudfront | Cloudfront distribution should have Access Logging configured |
| aws-s3-ignore-public-acls | aws | s3 | S3 Access Block should Ignore Public Acl |
| aws-s3-block-public-acls | aws | s3 | S3 Access block should block public ACL |
| aws-s3-no-public-buckets | aws | s3 | S3 Access block should restrict public bucket to limit access |
| aws-s3-block-public-policy | aws | s3 | S3 Access block should block public policy |
| aws-s3-enable-versioning | aws | s3 | S3 Data should be versioned |
| aws-ecr-enforce-immutable-repository | aws | ecr | ECR images tags shouldn't be mutable. |
| aws-ec2-enforce-http-token-imds | aws | ec2 | aws_instance should activate session tokens for Instance Metadata Service. |
| aws-codebuild-enable-encryption | aws | codebuild | CodeBuild Project artifacts encryption should not be disabled |
| aws-dynamodb-enable-at-rest-encryption | aws | dynamodb | DAX Cluster should always encrypt data at rest |
| aws-vpc-no-default-vpc | aws | vpc | AWS best practice to not use the default VPC for workflows |
| aws-elb-drop-invalid-headers | aws | elb | Load balancers should drop invalid headers |
| aws-workspace-enable-disk-encryption | aws | workspace | Root and user volumes on Workspaces should be encrypted |
| aws-config-aggregate-all-regions | aws | config | Config configuration aggregator should be using all regions for source |
| aws-dynamodb-enable-recovery | aws | dynamodb | Point in time recovery should be enabled to protect DynamoDB table |
| aws-redshift-non-default-vpc-deployment | aws | redshift | Redshift cluster should be deployed into a specific VPC |
| aws-elasticache-enable-backup-retention | aws | elasticache | Redis cluster should have backup retention turned on |
| aws-cloudwatch-log-group-customer-key | aws | cloudwatch | CloudWatch log groups should be encrypted using CMK |
| aws-ecs-enable-container-insight | aws | ecs | ECS clusters should have container insights enabled |
| aws-rds-backup-retention-specified | aws | rds | RDS Cluster and RDS instance should have backup retention longer than default 1 day |
| aws-dynamodb-table-customer-key | aws | dynamodb | DynamoDB tables should use at rest encryption with a Customer Managed Key |
| aws-ecr-repository-customer-key | aws | ecr | ECR Repository should use customer managed keys to allow more control |
| aws-redshift-encryption-customer-key | aws | redshift | Redshift clusters should use at rest encryption |
| aws-ssm-secret-use-customer-key | aws | ssm | Secrets Manager should use customer managed keys |
| aws-ecs-enable-in-transit-encryption | aws | ecs | ECS Task Definitions with EFS volumes should use in-transit encryption |
| aws-iam-block-kms-policy-wildcard | aws | iam | IAM customer managed policies should not allow decryption actions on all KMS keys |
| aws-s3-specify-public-access-block | aws | s3 | S3 buckets should each define an aws_s3_bucket_public_access_block |
| aws-iam-no-policy-wildcards | aws | iam | IAM policy should avoid use of wildcards and instead apply the principle of least privilege |
