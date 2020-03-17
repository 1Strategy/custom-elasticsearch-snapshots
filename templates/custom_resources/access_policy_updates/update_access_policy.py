"""Elasticsearch Domain Access Policy Updates Lambda

Executes Elasticsearch Domain Access Policy updates to allow AWS Services permissions to the domain
"""
from botocore.exceptions import ClientError
from crhelper import CfnResource
from typing import Tuple
import logging
import boto3
import json
import os


helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL')
es = boto3.client('es')


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Access Policy Updates function

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: dict
    """
    logger: 'logging.Logger' = log(__name__.upper())
    logger.info(f'EVENT: {event}')
    helper(event, context)


# @helper.update  # TODO: Need to separate this to avoid duplicate policy statements
@helper.create
def create(event: dict, _) -> None:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())
    config, policy = get_domain_config(event)
    config['DomainConfig']['AccessPolicies']['Options'] = update_policy_statements(event, policy)
    logger.info(f'Updating AccessPolicies: {config["DomainConfig"]["AccessPolicies"]["Options"]}')

    send_domain_config_updates(event, es, config)


@helper.delete
def delete(event: dict, _) -> None:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())
    config, policy = get_domain_config(event)
    config['DomainConfig']['AccessPolicies']['Options'] = remove_policy_statements(event, policy)
    logger.info(f'Removing Unused AccessPolicies: {config["DomainConfig"]["AccessPolicies"]["Options"]}')

    send_domain_config_updates(event, es, config)


def update_policy_statements(event: dict, policy: dict) -> dict:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())
    account_id = event['ServiceToken'].split(':')[4]

    role_arn: str
    for role_arn in event['ResourceProperties']['RoleArns']:
        statement: dict = {
            'Effect': 'Allow',
            'Principal': {
                'AWS': role_arn
            },
            'Action': 'es:ESHttp*',
            'Resource': f'arn:aws:es:{os.getenv("AWS_REGION")}:{account_id}:domain/{event["ResourceProperties"]["DomainName"]}/*',
        }
        if statement not in policy['Statement']:
            logger.info(f'Appending statement: {statement}')
            policy['Statement'].append(statement)

    return policy


def remove_policy_statements(event: dict, policy: dict) -> dict:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())

    for role_arn in event['ResourceProperties']['RoleArns']:
        for statement in policy['Statement']:
            if role_arn in statement['Principal']['AWS']:
                logger.info(f'Removing statement: {statement}')
                policy['Statement'].remove(statement)

    return policy


def get_domain_config(event: dict) -> Tuple[dict, dict]:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())

    try:
        config: dict = es.describe_elasticsearch_domain_config(DomainName=event['ResourceProperties']['DomainName'])
        policy: dict = json.loads(config['DomainConfig']['AccessPolicies']['Options'])
        return config, policy
    except ClientError as e:
        logger.error(e)
        helper.init_failure(e)


def send_domain_config_updates(event: dict, es_conn, config: dict) -> None:
    """
    """
    logger: 'logging.Logger' = log(__name__.upper())

    try:
        es_conn.update_elasticsearch_domain_config(
            DomainName=event['ResourceProperties']['DomainName'],
            AccessPolicies=json.dumps(config['DomainConfig']['AccessPolicies']['Options']),
        )
        logger.info('Completed the Access Policy Updates')
    except ClientError as e:
        logger.error(e)
        helper.init_failure(e)


def log(name='aws_entity', logging_level=logging.INFO) -> 'logging.Logger':
    """Instantiate a logger
    """

    logger: 'logging.Logger' = logging.getLogger(name)
    if len(logger.handlers) < 1:
        log_handler: logging.StreamHandler = logging.StreamHandler()
        formatter: logging.Formatter = logging.Formatter('%(levelname)-8s %(asctime)s %(name)-12s %(message)s')
        log_handler.setFormatter(formatter)
        logger.propagate = False
        logger.addHandler(log_handler)
        logger.setLevel(logging_level)
    return logger

