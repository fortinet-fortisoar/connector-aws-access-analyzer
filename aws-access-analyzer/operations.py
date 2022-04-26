""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """


import boto3
from connectors.core.connector import get_logger, ConnectorError
from .utils import _get_aws_client, _get_temp_credentials

logger = get_logger('aws-access-analyzer')
TEMP_CRED_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{}'

def remove_unwanted_param(params):
    try:
        params.pop('aws_region', None)
        params.pop('assume_role', None)
        params.pop('session_name', None)
        params.pop('role_arn', None)
        param_dict = {k: v for k, v in params.items() if v is not None and v != '' and v != {} and v != []}
        return param_dict
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)

def check_health(config):
    try:
        config_type = config.get('config_type')
        if config_type == "IAM Role":
            if _get_temp_credentials(config):
                return True
            else:
                logger.error('Invalid Role. Please verify is the role is associated to your instance.')
                raise ConnectorError('Invalid Role. Please verify is the role is associated to your instance.')
        else:
            aws_access_key = config.get('aws_access_key')
            aws_region = config.get('aws_region')
            aws_secret_access_key = config.get('aws_secret_access_key')
            client = boto3.client('sts', region_name=aws_region, aws_access_key_id=aws_access_key,
                                  aws_secret_access_key=aws_secret_access_key)
            account_id = client.get_caller_identity()["Account"]
            if account_id:
                return True
            else:
                logger.error('Invalid Region name or Aws Access Key ID or Aws Secret Access Key')
                raise ConnectorError('Invalid Region name or Aws Access Key ID or Aws Secret Access Key')
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def list_analyzers(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    size = params.get("size")
    type = params.get("type") # 'ACCOUNT' | 'ORGANIZATION'
    next_token = params.get("next_token", "") # optional/ not required for first time.
    response = client.list_analyzers(
        maxResults=size,
        nextToken=next_token,
        type=type
    )
    return response


def list_analyzers_only_names(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    type = params.get("type") # 'ACCOUNT' | 'ORGANIZATION'
    if type is None or len(type) == 0:
        return []
    response = client.list_analyzers(
        type=type
    )
    names = []
    for analyzer in response.get("analyzers", []):
        names.append(analyzer.get("name"))
    return names


def list_analyzers_only_arn(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    type = params.get("type") # 'ACCOUNT' | 'ORGANIZATION'
    if type is None or len(type) == 0:
        return []
    response = client.list_analyzers(
        type=type
    )
    arn = []
    for analyzer in response.get("analyzers", []):
        arn.append(analyzer.get("arn"))
    return arn


def get_analyzers(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_name = params.get("analyzer_name")
    response = client.get_analyzer(
        analyzerName=analyzer_name
    )
    return response


def list_analyzed_resources(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    size = params.get("size")
    resource_type = params.get("resource_type") # 'AWS::S3::Bucket' | 'AWS::IAM::Role' | 'AWS::SQS::Queue' | 'AWS::Lambda::Function' | 'AWS::Lambda::LayerVersion' | 'AWS::KMS::Key' | 'AWS::SecretsManager::Secret'
    next_token = params.get("next_token") # optional/ not required for first time.
    if next_token and len(next_token)>0:
        response = client.list_analyzed_resources(
            analyzerArn=analyzer_arn,
            maxResults=size,
            nextToken=next_token,
            resourceType=resource_type
        )
    else:
        response = client.list_analyzed_resources(
            analyzerArn=analyzer_arn,
            maxResults=size,
            resourceType=resource_type
        )
    return response


#helper operation for get analyzed resources
def list_analyzed_resources_only_arns(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    resource_type = params.get("resource_type") # 'AWS::S3::Bucket' | 'AWS::IAM::Role' | 'AWS::SQS::Queue' | 'AWS::Lambda::Function' | 'AWS::Lambda::LayerVersion' | 'AWS::KMS::Key' | 'AWS::SecretsManager::Secret'
    if analyzer_arn is None or len(analyzer_arn) == 0 or resource_type is None or len(resource_type) == 0:
        return []
    response = client.list_analyzed_resources(
        analyzerArn=analyzer_arn,
        resourceType=resource_type
    )
    arns = []
    for i in response.get("analyzedResources", []):
        arns.append(i.get("resourceArn"))
    return arns


def get_analyzed_resources(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    resource_arn = params.get("resource_arn")
    response = client.get_analyzed_resource(
        analyzerArn=analyzer_arn,
        resourceArn=resource_arn
    )
    return response


def list_findings(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    size = params.get("size", 10)
    filter = params.get("filter", {})
    sort = params.get("sort", {})
    next_token = params.get("next_token") # optional and not required in first time
    if next_token and len(next_token)>0 and sort:
        response = client.list_findings(
            analyzerArn=analyzer_arn,
            filter=filter,
            maxResults=size,
            nextToken=next_token,
            sort=sort
        )
    elif sort:
        response = client.list_findings(
            analyzerArn=analyzer_arn,
            filter=filter,
            maxResults=size,
            sort=sort
        )
    elif next_token:
        response = client.list_findings(
            analyzerArn=analyzer_arn,
            filter=filter,
            maxResults=size,
            nextToken=next_token
        )
    else:
        response = client.list_findings(
            analyzerArn=analyzer_arn,
            filter=filter,
            maxResults=size,
        )
    return response


def get_findings(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    id = params.get("id")
    response = client.get_finding(
        analyzerArn=analyzer_arn,
        id=id
    )
    return response


def start_resource_scan(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    resource_arn = params.get("resource_arn")
    response = client.start_resource_scan(
        analyzerArn=analyzer_arn,
        resourceArn=resource_arn
    )
    return response


def update_findings(config, params):
    client = _get_aws_client(config, params, 'accessanalyzer')
    analyzer_arn = params.get("analyzer_arn")
    resource_arn = params.get("resource_arn")
    client_token = params.get("client_token")
    ids = params.get("ids") # json list
    status = params.get("status") # 'ACTIVE' | 'ARCHIVED'
    response = client.update_findings(
        analyzerArn=analyzer_arn,
        clientToken=client_token,
        ids=ids,
        resourceArn=resource_arn,
        status=status
    )
    return response


operations = {
    "list_analyzers": list_analyzers,
    "list_analyzers_only_names": list_analyzers_only_names,
    "list_analyzers_only_arn": list_analyzers_only_arn,
    "get_analyzers": get_analyzers,
    "list_analyzed_resources": list_analyzed_resources,
    "get_analyzed_resources": get_analyzed_resources,
    "list_findings": list_findings,
    "get_findings": get_findings,
    "start_resource_scan": start_resource_scan,
    "update_findings": update_findings
}