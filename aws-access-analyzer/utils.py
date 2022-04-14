""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import boto3
import json, requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('aws-cloudtrail')
TEMP_CRED_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{}'



def _get_temp_credentials(config):
    try:
        aws_iam_role = config.get('aws_iam_role')
        url = TEMP_CRED_ENDPOINT.format(aws_iam_role)
        resp = requests.get(url=url, verify=config.get('verify_ssl'))
        if resp.ok:
            data = json.loads(resp.text)
            return data
        else:
            logger.error(str(resp.text))
            raise ConnectorError("Unable to validate the credentials")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _assume_a_role(data, params, aws_region):
    try:
        client = boto3.client('sts', region_name=aws_region, aws_access_key_id=data.get('AccessKeyId'),
                              aws_secret_access_key=data.get('SecretAccessKey'),
                              aws_session_token=data.get('Token'))
        role_arn = params.get('role_arn')
        session_name = params.get('session_name')
        response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        aws_region2 = params.get('aws_region')
        aws_session = boto3.session.Session(region_name=aws_region2,
                                            aws_access_key_id=response['Credentials']['AccessKeyId'],
                                            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                            aws_session_token=response['Credentials']['SessionToken'])
        return aws_session
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_session(config, params):
    try:
        config_type = config.get('config_type')
        assume_role = params.get("assume_role", False)
        if config_type == "IAM Role":
            if not assume_role:
                raise ConnectorError("Please Assume a Role to execute actions")

            aws_region = params.get('aws_region')
            data = _get_temp_credentials(config)
            aws_session = _assume_a_role(data, params, aws_region)
            return aws_session

        else:
            aws_access_key = config.get('aws_access_key')
            aws_region = config.get('aws_region')
            aws_secret_access_key = config.get('aws_secret_access_key')
            if assume_role:
                data = {
                    "AccessKeyId": aws_access_key,
                    "SecretAccessKey": aws_secret_access_key,
                    "Token": None
                }
                aws_session = _assume_a_role(data, params, aws_region)
            else:
                aws_session = boto3.session.Session(region_name=aws_region, aws_access_key_id=aws_access_key,
                                                aws_secret_access_key=aws_secret_access_key)
            return aws_session
    except Exception as Err:
        raise ConnectorError(Err)


def _get_aws_client(config, params, service):
    try:
        aws_session = _get_session(config, params)
        aws_client = aws_session.client(service, verify=config.get('verify_ssl'))
        return aws_client
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)

