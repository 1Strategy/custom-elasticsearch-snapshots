"""
"""
from botocore.exceptions import ClientError
from crhelper import CfnResource
import logging
import boto3
import json

try:
    import botostubs
except ModuleNotFoundError:
    pass


helper = CfnResource(json_logging=False, log_level='DEBUG', boto_level='CRITICAL')


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Access Policy Updates function

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: dict
    """
    logger: logging.Logger = log('ACCESS POLICY UPDATES HANDLER')
    logger.info(f'EVENT: {event}')
    helper(event, context)


@helper.update  # TODO: Need to separate this to avoid duplicate policy statements
@helper.create
def create(event: dict, _) -> None:
    """
    """
    logger: logging.Logger = log('ACCESS POLICY UPDATES CREATE HANDLER')
    es = boto3.client('es')  # type: botostubs.ElasticsearchService
    config = es.describe_elasticsearch_domain_config(DomainName=event['ResourceProperties']['DomainName'])  # type: botostubs.ElasticsearchService.describe_elasticsearch_domain_config
    policy: dict = json.loads(config['DomainConfig']['AccessPolicies']['Options'])
    region = event['ServiceToken'].split(':')[3]
    account_id = event['ServiceToken'].split(':')[4]

    snapshot_role_policy: dict = {
        'Effect': 'Allow',
        'Principal': {
            'AWS': event['ResourceProperties']['CreateSnapshotFunctionRoleArn']
        },
        'Action': 'es:ESHttp*',
        'Resource': f'arn:aws:es:{region}:{account_id}:domain/{event["ResourceProperties"]["DomainName"]}/*',
    }

    snapshot_repo_role_policy: dict = {
        'Effect': 'Allow',
        'Principal': {
            'AWS': event['ResourceProperties']['CreateSnapshotRepoFunctionRoleArn']
        },
        'Action': 'es:ESHttp*',
        'Resource': f'arn:aws:es:{region}:{account_id}:domain/{event["ResourceProperties"]["DomainName"]}/*',
    }

    policy['Statement'].append(snapshot_role_policy)
    policy['Statement'].append(snapshot_repo_role_policy)
    config['DomainConfig']['AccessPolicies']['Options'] = policy

    try:
        logger.info(f'Updating AccessPolicies: {config["DomainConfig"]["AccessPolicies"]["Options"]}')
        es.update_elasticsearch_domain_config(
            DomainName=event['ResourceProperties']['DomainName'],
            AccessPolicies=json.dumps(config['DomainConfig']['AccessPolicies']['Options']),
        )
    except ClientError as e:
        logger.error(e)
        return

    logger.info('Completed the Access Policy Updates')
    pass


@helper.delete
def delete(event: dict, _) -> None:
    """
    """
    logger: logging.Logger = log('ACCESS POLICY UPDATES DELETE HANDLER')
    logger.info('Delete handler triggered')
    pass


def log(name='aws_entity', logging_level=logging.INFO) -> logging.Logger:
    """Instantiate a logger
    """

    logger: logging.Logger = logging.getLogger(name)
    if len(logger.handlers) < 1:
        log_handler: logging.StreamHandler = logging.StreamHandler()
        formatter: logging.Formatter = logging.Formatter('%(levelname)-8s %(asctime)s %(name)-12s %(message)s')
        log_handler.setFormatter(formatter)
        logger.propagate = False
        logger.addHandler(log_handler)
        logger.setLevel(logging_level)
    return logger

