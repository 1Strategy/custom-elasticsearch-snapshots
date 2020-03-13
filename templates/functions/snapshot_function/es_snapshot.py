"""
Elasticsearch Snapshot Lambda

Executes Elasticsearch Domain Snapshots on a frequency that differs from the daily default provided by AWS Elasticsearch
"""
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from datetime import datetime as dt
import logging
import boto3
import os


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Snapshot function

    :type: dict
    :param: event: aws cloudwatch schedule event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: dict
    """
    logger: logging.Logger = log('MULESOFT SNAPSHOT HANDLER')
    logger.info(f'EVENT: {event}')

    repo_name: str = os.getenv('REPO_NAME')
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, event['region'], 'es', session_token=credentials.token)

    es_host: str = os.getenv('ES_HOST')
    snapshot_name: str = str(dt.utcnow()).replace(' ', '-').replace(':', '-').split('.')[0]

    es = Elasticsearch(
        hosts=['https://' + es_host],
        http_auth=awsauth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection
    )

    logger.info(f'ES INSTANCE: {es.ping()}')

    response = es.snapshot.create(repository=repo_name, snapshot=snapshot_name)
    # try:
    #     response = es.snapshot.create(repository=repo_name, snapshot=snapshot_name)
    #     logger.info(f'Response: {response}')
    # except Exception as e:
    #     logger.error(e)
    #     return

    logger.info(f'Response: {response}')


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
