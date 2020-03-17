"""Elasticsearch Snapshot Lambda

Executes Elasticsearch Domain Snapshots on customizable schedule, differing from the provided snapshots by AWS Elasticsearch Service
"""
from elasticsearch.exceptions import ConnectionError, ConnectionTimeout
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from datetime import datetime as dt
import logging
import boto3
import os


def handler(event: dict, _) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Snapshot function

    :type: dict
    :param: event: aws cloudwatch schedule event

    :type: dict
    :param: _: (Unused) aws lambda function environment context

    :rtype: None
    """
    logger: logging.Logger = log(__name__.upper())
    logger.info(f'EVENT: {event}')

    snapshot_name: str = str(dt.utcnow()).replace(' ', '-').replace(':', '-').split('.')[0]
    es: 'Elasticsearch' = get_es_connection()
    logger.info(f'ES INSTANCE CONNECTION ACTIVE: {es.ping()}')

    try:
        response = es.snapshot.create(repository=os.getenv('REPO_NAME'), snapshot=snapshot_name)
        logger.info(f'RESPONSE: {response}')
    except (ConnectionError, ConnectionTimeout) as e:
        logger.error(e)


def get_signature() -> 'AWS4Auth':
    """Construct an AWS4Auth object for use with STS temporary credentials. The `x-amz-security-token` header is added with the session token.

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


def get_es_connection() -> 'Elasticsearch':
    """Elasticsearch low-level client. Provides a straightforward mapping from Python to ES REST endpoints

    :rtype: 'Elasticsearch'
    """
    logger: logging.Logger = log(__name__.upper())
    logger.info('Getting Elasticsearch Connection')

    return Elasticsearch(
        hosts=['https://' + os.getenv('ES_HOST')],
        http_auth=get_signature(),
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )


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
