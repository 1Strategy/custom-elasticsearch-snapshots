1. Clone the repo:
2. Install the dependencies for Lambda Layer:
```
pipenv run pip freeze > requirements.txt
pip install -r requirements.txt -t ./templates/functions/function_dependencies/http_requests/python/.
```
3. Add the following parameters to a `sandbox.json` file in `./parameters/us-west-2/sandbox.json`:
```
[
  "IsElasticsearchInVpc=false",
  "SubnetIds=subnet-0f43889c0dab70fdc",
  "VpcId=vpc-0faa81d575a6041bf",
  "DomainName=public-domain",
  "SnapshotRepoName=public-domain-snapshots",
  "SnapshotScheduleExpression=rate(5 minutes)",
  "ElasticsearchDomainUrl=search-public-domain-5pcllp64oo74ezfwulbyxhrs2i.us-west-2.es.amazonaws.com",
  "ElasticsearchDomainSecurityGroupId=sg-050ea5d9209fc378b"
]
```
4. Run the following commands to package and deploy the template:
```
aws cloudformation package \
    --template-file templates/elasticsearch_snapshots.yaml \
    --s3-bucket "1s-scott" \
    --output-template-file deploy/deploy_snapshots.yaml \
    --region "us-west-2" && \
aws cloudformation deploy \
    --stack-name "demo-domain-custom-snapshots" \
    --template-file deploy/deploy_snapshots.yaml \
    --parameter-overrides "file://parameters/us-west-2/sandbox.json" \
    --capabilities CAPABILITY_IAM \
    --region "us-west-2"
 ```
