"""Elasticsearch Domain Security Group Updates Lambda

Executes Elasticsearch Domain Security Group Updates to allow ingress from VPC-based Lambdas
"""
from botocore.exceptions import ClientError
from crhelper import CfnResource
import logging
import boto3


helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL')


def handler(event: dict, context: dict) -> None:
    """AWS Lambda function handler - Elasticsearch Domain Security Group Updates function

    :type: dict
    :param: event: aws cloudformation custom resource event

    :type: dict
    :param: context: aws lambda function environment context

    :rtype: dict
    """
    logger: logging.Logger = log(__name__.upper())
    logger.info(f'EVENT: {event}')
    helper(event, context)


@helper.update
@helper.create
def create(event, context):
    logger: logging.Logger = log(__name__.upper())
    ec2 = boto3.resource('ec2')
    domain_sg = ec2.SecurityGroup(event['ResourceProperties']['DomainSecurityGroupId'])

    try:
        domain_sg.authorize_ingress(
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': event['ResourceProperties']['SnapshotFunctionSecurityGroupId']
                        }
                    ]
                }
            ],
        )
        logger.info('Successfully created security group ingress rules for ES Domain')
    except ClientError as e:
        logger.info(e)
        helper.init_failure(e)


@helper.delete
def delete(event, context):
    logger: logging.Logger = log(__name__.upper())
    ec2 = boto3.resource('ec2')
    domain_sg = ec2.SecurityGroup(event['ResourceProperties']['DomainSecurityGroupId'])
    try:
        domain_sg.revoke_ingress(
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'UserIdGroupPairs': [
                        {
                            'GroupId': event['ResourceProperties']['SnapshotFunctionSecurityGroupId']
                        }
                    ]
                }
            ],
        )

        logger.info('Successfully deleted security group ingress rules for ES Domain')
    except ClientError as e:
        logger.error(e)
        helper.init_failure(e)


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
