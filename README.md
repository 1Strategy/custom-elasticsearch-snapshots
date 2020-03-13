# Mulesoft Real-time Logging Analytics
---
This template is used to create a real-time logging analytics solution for Mulesoft-based application logs. The solution leverages Amazon Kinesis Firehose in combination with an Amazon Elasticsearch Domain. Kinesis Firehose and the Elasticsearch domain will be deployed into Driscoll's logging account, and the Kinesis Firehose Delivery Stream will be accessed via VPN Tunneling.

![](./images/mulesoft-real-time-logging-analytics.png)

<br /><br />

## Getting Started
---
This project takes advantage of the AWS CLI to package and deploy the template. A set of CLI credentials (*AccessKey and SecretKey*) with permissions to deploy all of the resources defined in the template is required. This requires both the install ation of the AWS CLI as well as a SAML Authentication tool such as [SAML2AWS](https://github.com/Versent/saml2aws).

<br /><br />

## Prerequisites
---

* Installing AWS CLI:  https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-install.html
* Configuring AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html
* Installing & Configuring SAML2AWS: https://github.com/Versent/saml2aws

<br /><br />

## Deploying the Templates via AWS CLI for the first time
---

### Parameters
Review and update the parameters for each template in the deployment. They are currently configured to work with the Oregon (us-west-2) Region.

Below is an example of how the parameters should be organized by region if this deployment extends into multiple regions for any reason:

```
parameters
└── us-west-2
    ├── auth
    │   └── parameters.json
    ├── domain
    │   └── parameters.json
    ├── firehose
    │   └── parameters.json
    └── snapshots
        └── parameters.json
└── us-west-1
    ├── auth
    │   └── parameters.json
    ├── domain
    │   └── parameters.json
    ├── firehose
    │   └── parameters.json
    └── snapshots
        └── parameters.json
...
```

Parameter files are located in the project directory under the [Parameters/](./parameters) directory. For example, the [parameters.json](./parameters/us-west-2/firehose/parameters.json) file associated with the Kinesis Firehose deployment(s) is structured as a list of stringified `key=value` pairs:

```json
[
    "VpcId=vpc-03f33becca688c9df",
    "SubnetIds=subnet-0f000e44a4e9bd4db,subnet-0532f55f7474b5e65",
    "ElasticsearchDomainEndpoint=/driscolls/elasticsearch/endpoint",
    "ElasticsearchDomainSecurityGroupId=/driscolls/elasticsearch/security_group",
    "ElasticsearchBufferInterval=120",
    "ElasticsearchBufferSize=1",
    "CloudWatchLogging=true",
    "ProcessorRetryNumber=2",
    "CompressionFormat=GZIP",
    "TransformFunctionRole=/driscolls/firehost/transform/role/arn"
]
```

<br /><br />

### Define all necessary resource tags in a json file:

*`tags.json`*:
```
[
    "Business_Unit=CloudEngineering",
    "Owner=Jane Doe",
    "Project=Cross Account Delivery Stream"
]
```

<br /><br />

### Retrieve your temporary access credentials from your SAML authentication provider:

If using SAML2AWS:
```
$ saml2aws login
Using IDP Account default to access Okta https://driscolls.okta.com/home/amazon_aws/00000000000000000000?fromHome=true
To use saved password just hit enter.
? Username user.name@driscolls.com
? Password *********************
Authenticating as user.name@driscolls.com ...
Selected role: arn:aws:iam::123456789012:role/log-archive-acct-admins
Requesting AWS credentials using SAML assertion
Logged in as: arn:aws:sts::123456789012:assumed-role/log-archive-acct-admins/user.name@driscolls.com

Your new access key pair has been stored in the AWS configuration
Note that it will expire at 2020-01-23 10:18:13 -0800 PST
To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile driscolls ec2 describe-instances).
```

<br /><br />

### Utilize the `deploy.sh` script for a bulk deployment of all four templates:

```
# ./deploy.sh <StackName> <ArtifactBucket> <Region> <Profile(optional)>
$ ./deploy.sh mulesoft-logs driscolls-lambda-artifacts us-west-2 driscolls
```

<br /><br />

 ## Authors
 ---
* Will Nave - [1Strategy](https://www.1strategy.com)
* Scott Schmidt - [1Strategy](https://www.1strategy.com)

<br />

## License
---
Copyright 2019 1Strategy

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

<br />

## References
---
* AWS CloudFormation Best Practices: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/best-practices.html
* AWS CloudFormation Template Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-reference.html
* AWS Elasticsearch Service with Firehose Delivery Stream: https://binx.io/blog/2018/11/16/elasticsearch-service-firehose/
* Loading Streaming Data into Amazon ES from Amazon Kinesis Data Firehose: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-aws-integrations.html#es-aws-integrations-fh
* Real-Time Data Streaming with Python + AWS Kinesis: https://medium.com/swlh/real-time-data-streaming-with-python-aws-kinesis-how-to-part-1-cd56feb6fd0f


