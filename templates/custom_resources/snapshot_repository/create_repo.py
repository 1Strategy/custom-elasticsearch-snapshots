"""
Elasticsearch Domain Snapshot Repository Lambda

Executes Elasticsearch Domain Snapshot Repository to allow ingress from Kinesis Firehose
"""
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
from crhelper import CfnResource
import logging
import boto3

try:
    import botostubs
except ModuleNotFoundError:
    pass


helper = CfnResource(json_logging=True, log_level='DEBUG', boto_level='CRITICAL')


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Snapshot Repository function

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: dict
    """
    logger: logging.Logger = log('ES DOMAIN SNAPSHOT REPOSITORY HANDLER')
    logger.info(f'EVENT: {event}')
    helper(event, context)


@helper.update
@helper.create
def create(event, context):
    logger: logging.Logger = log('ES DOMAIN SNAPSHOT REPOSITORY CREATE HANDLER')
    logger.info('Create Triggered')

    credentials = boto3.Session().get_credentials()
    region = event['ServiceToken'].split(':')[3]

    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, 'es',
                       session_token=credentials.token)

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
            'region': region,
            'role_arn': event['ResourceProperties']['ElasticsearchDomainRoleArn']
        }
    }

    try:
        res = es.snapshot.create_repository(
            repository=event['ResourceProperties']['SnapshotRepoName'],
            body=snapshot_body
        )
    except Exception as e:
        logger.error(e)
        return

    logger.info(f'RESPONSE: {res}')


@helper.delete
def delete(event, context):
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











