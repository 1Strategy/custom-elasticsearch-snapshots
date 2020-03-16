"""
Elasticsearch Domain Snapshot Repository Lambda

Executes Lambda Function to create a new Elasticsearch Domain Snapshot Repository
"""
from elasticsearch.exceptions import ConnectionError, ConnectionTimeout
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from crhelper import CfnResource
import logging
import boto3
import os


helper = CfnResource(json_logging=True, log_level='INFO', boto_level='CRITICAL')


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Snapshot Repository function

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: None
    """
    logger: logging.Logger = log('ELASTICSEARCH SNAPSHOT REPOSITORY HANDLER')
    logger.info(f'EVENT: {event}')
    helper(event, context)


@helper.update
@helper.create
def create(event: dict, _) -> None:
    logger: logging.Logger = log('ES DOMAIN SNAPSHOT REPOSITORY CREATE HANDLER')
    logger.info('Create Triggered')

    credentials = boto3.Session().get_credentials()

    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        os.getenv('AWS_REGION'),
        'es',
        session_token=credentials.token
    )

    es_host = event['ResourceProperties']['ElasticsearchDomainUrl']
    es = Elasticsearch(
        hosts=['https://' + es_host],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )

    logger.info(es)

    snapshot_body = {
        'type': 's3',
        'settings': {
            'bucket': event['ResourceProperties']['SnapshotBucket'],
            'region': os.getenv('AWS_REGION'),
            'role_arn': event['ResourceProperties']['ElasticsearchDomainRoleArn']
        }
    }

    try:
        res = es.snapshot.create_repository(
            repository=event['ResourceProperties']['SnapshotRepoName'],
            body=snapshot_body
        )
    except (ConnectionError, ConnectionTimeout) as e:
        logger.error(e)
        return

    logger.info(f'RESPONSE: {res}')


@helper.delete
def delete(event, _):
    logger: logging.Logger = log('ES DOMAIN SNAPSHOT REPOSITORY DELETE HANDLER')
    logger.info('Delete triggered')


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











