# AWS collection

Use only AWS accounts you are authorized to assess. Configure a short-lived audit profile using your normal AWS authentication flow. The application never creates a role or modifies policies.

## Scope

The account ID is mandatory and checked with STS before any inventory call. IAM roles and their attached/inline policies are collected across the account. EC2 security groups are collected in each explicitly supplied region. Only explicitly supplied bucket names are inspected, using `ExpectedBucketOwner`. Bucket names may expose business information; keep collected snapshots and reports private.

The example policy below grants only the implemented reads. Narrow S3 resources to the approved buckets. Use the appropriate ARN partition for GovCloud or China. Authorization details include policy documents, so treat the output as sensitive configuration.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["iam:GetAccountAuthorizationDetails", "ec2:DescribeSecurityGroups"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetAccountPublicAccessBlock",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketPolicyStatus", "s3:GetBucketPublicAccessBlock"],
      "Resource": ["arn:aws:s3:::YOUR_APPROVED_BUCKET"]
    }
  ]
}
```

STS `GetCallerIdentity` does not require an allow statement. Bedrock is a separate optional capability and requires `bedrock:InvokeModel` on your approved model/inference profile resources. Do not give the model any AWS write permissions for this workflow.

## Missing data

API errors, pagination anomalies and missing managed-policy/boundary documents are preserved as coverage warnings. Incomplete roles cannot yield confirmed modeled permissions. An S3 read failure becomes unknown rather than a negative check. A `NoSuchPublicAccessBlockConfiguration` response is conservatively treated as unknown in this release, rather than inferring all organization-level controls. Snapshots with collection errors are saved for inspection and the command exits 2.

The collector retrieves effective account/bucket `RestrictPublicBuckets` settings for existing public-policy evaluation. `BlockPublicPolicy` prevents new public policies; by itself it does not disable an already existing policy. The release does not claim to prove object accessibility or evaluate ACLs, access points and organization policies. See [AWS Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html).

## References

- [IAM authorization inventory API](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_account_authorization_details.html)
- [S3 bucket policy status API](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_policy_status.html)
- [IAM policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [Bedrock Converse API](https://docs.aws.amazon.com/boto3/latest/reference/services/bedrock-runtime/client/converse.html)
