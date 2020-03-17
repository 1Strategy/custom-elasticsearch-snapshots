"""Elasticsearch Domain Snapshot Repository Lambda

Executes Lambda Function to create a new Elasticsearch Domain Snapshot Repository
"""
from elasticsearch.exceptions import ConnectionError, ConnectionTimeout, NotFoundError
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
    logger: logging.Logger = log(__name__.upper())
    logger.info(f'EVENT: {event}')
    helper(event, context)


@helper.create
def create(event: dict, _) -> None:
    """Creates Elasticsearch Snapshot Repository

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: _: (Unused) aws lambda function environment context

    :rtype: None
    """
    logger: logging.Logger = log(__name__.upper())

    es = get_es_connection(event)
    logger.info(f'Elasticsearch Connection Active: {es.ping()}')
    create_repository(event, es)


@helper.update
def update(event: dict, _) -> None:
    """Updates Elasticsearch Snapshot Repository

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: _: (Unused) aws lambda function environment context

    :rtype: None
    """
    logger: logging.Logger = log(__name__.upper())

    es: 'Elasticsearch' = get_es_connection(event)
    logger.info(f'Elasticsearch Connection Active: {es.ping()}')

    repo_name: str = event['ResourceProperties']['SnapshotRepoName']

    try:
        es.snapshot.get_repository(repository=repo_name)
        logger.info('Repository already exists; skipping update')
        logger.info(f'This update has not made changes to the existing repository: {repo_name}')
    except NotFoundError:
        logger.info('Repository does not exist')
        create_repository(event, es)


@helper.delete
def delete(event: dict, _) -> None:
    """Deletes Elasticsearch Snapshot Repository

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: _: (Unused) aws lambda function environment context

    :rtype: None
    """
    logger: logging.Logger = log(__name__.upper())

    es: 'Elasticsearch' = get_es_connection(event)
    logger.info(f'Elasticsearch Connection Active: {es.ping()}')

    try:
        res = es.snapshot.delete_repository(repository=event['ResourceProperties']['SnapshotRepoName'])
        logger.info(f'Removal of Snapshot Repository complete: {res}')
    except (ConnectionError, ConnectionTimeout) as e:
        logger.error(e)
        helper.init_failure(e)


def get_signature() -> 'AWS4Auth':
    """Construct an AWS4Auth object for use with STS temporary credentials.
    The `x-amz-security-token` header is added with the session token.

    :rtype: 'AWS4Auth'
    """
    logger: logging.Logger = log(__name__.upper())
    logger.info('Getting credentials')
    credentials = boto3.Session().get_credentials()

    return AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        os.getenv('AWS_REGION'),
        'es',
        session_token=credentials.token
    )


def get_es_connection(event: dict) -> 'Elasticsearch':
    """Elasticsearch low-level client. Provides a straightforward mapping from Python to ES REST endpoints

    :type: dict
    :param: event: aws cloudformation custom resource event

    :rtype: 'Elasticsearch'
    """
    logger: logging.Logger = log(__name__.upper())
    logger.info('Getting Elasticsearch Connection')

    return Elasticsearch(
        hosts=['https://' + event['ResourceProperties']['ElasticsearchDomainUrl']],
        http_auth=get_signature(),
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )


def create_repository(event: dict, es_conn) -> None:
    """
    """
    logger: logging.Logger = log(__name__.upper())

    snapshot_body = {
        'type': 's3',
        'settings': {
            'bucket': event['ResourceProperties']['SnapshotBucket'],
            'region': os.getenv('AWS_REGION'),
            'role_arn': event['ResourceProperties']['ElasticsearchDomainRoleArn']
        }
    }

    try:
        res = es_conn.snapshot.create_repository(
            repository=event['ResourceProperties']['SnapshotRepoName'],
            body=snapshot_body
        )
        logger.info(f'Creation of Snapshot Repository complete: {res}')
    except (ConnectionError, ConnectionTimeout) as e:
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
