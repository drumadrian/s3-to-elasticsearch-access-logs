from __future__ import print_function
import json
import urllib.parse
import boto3
from elasticsearch import Elasticsearch, RequestsHttpConnection
import requests
from datetime import datetime
from s3logparse import s3logparse
import os
from tempfile import NamedTemporaryFile
import traceback
from aws_xray_sdk import core
core.patch_all()

import gzip
from base64 import b64decode
from requests_aws4auth import AWS4Auth



# Notes:
# https://docs.aws.amazon.com/code-samples/latest/catalog/python-s3-get_object.py.html
# https://forums.aws.amazon.com/thread.jspa?threadID=221549
# https://stackoverflow.com/questions/32000934/python-print-a-variables-name-and-value
# https://pypi.org/project/s3-log-parse/
# https://www.geeksforgeeks.org/python-dictionary/
# https://stackoverflow.com/questions/44381249/treat-a-string-as-a-file-in-python
# https://github.com/elastic/elasticsearch-py
# https://docs.aws.amazon.com/lambda/latest/dg/running-lambda-code.html


print('Loading function')

##################################################################################################
# Initialize boto3 client at global scope for connection reuse
#  Get environment variables for reuse
##################################################################################################
client = boto3.client('ssm')
s3 = boto3.client('s3')

host = os.environ.get('ES_ENDPOINT')
index = os.environ.get('ES_INDEX')
region = os.environ.get('ES_REGION')



##################################################################################################
# AWS Lambda hander invoked first
##################################################################################################
def lambda_handler(event, context):
    # print("Received event: " + json.dumps(event, indent=2))

    ######################################################################
    # Get all parameters containing credentials for this app
    ######################################################################

    region = os.environ.get('ES_REGION')
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

    host = os.environ.get('ES_ENDPOINT')
    index = os.environ.get('index_name')
    type = os.environ.get('ES_DOC_TYPE')
    event_type = ""

    headers = {"Content-Type": "application/json"}

        

    ######################################################################
    # Get data from S3
    ######################################################################
    print('Getting data from S3 records...')

    print(event)
    exit()






    ##################################################################################################
    #Now put that data in ElasticSearch! 
    ##################################################################################################
    count = 0
    errors = 0
    print('Processing records...')
    for record in logEvents:
        id = record['id']
        document = json.loads(record['message'])
        event_type = ??
        url = host + '/' + index + event_type + '/' + type + '/'
        r = requests.put(url + id, auth=awsauth, json=document, headers=headers)
        if (r.status_code > 299):
            print('Failed to post record{}:\n  - STATUS {} - {}'.format(id, r.status_code, r.text))
            errors = 0
        else:
            count += 1
    print('{} records posted to Elasticsearch.'.format(count))
    if (errors > 0):
        print('{} failed records not posted to Elasticsearch.'.format(count))

