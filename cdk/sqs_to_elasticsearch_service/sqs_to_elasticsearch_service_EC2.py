from __future__ import print_function
import os
import logging
import boto3
import base64
from botocore.exceptions import ClientError
import gzip
import json

import io
import botocore
import pandas as pd
import csv
import datetime as datetime




################################################################################################################
#   References
################################################################################################################
# https://stackoverflow.com/questions/37703634/how-to-import-a-text-file-on-aws-s3-into-pandas-without-writing-to-disk




################################################################################################################
#   Config
################################################################################################################
region = os.environ['AWS_REGION']
firehose_name = os.environ['FIREHOSE_NAME']
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_ID']
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_USERNAME']
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_PASSWORD']
logger = logging.getLogger()
# logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)






def get_elasticsearch_time(time_from_record):
    # Need:
    # 2018-04-23T10:45:13.899Z
    # Have:
    # [23/Nov/2020:07:43:07
    # Got:
    # 2020-Nov-23T07:43:07Z

    print('time_from_record=' + time_from_record)
    year = time_from_record[8:12]
    month = time_from_record[4:7]
    day = time_from_record[1:3]
    hour = time_from_record[13:15]
    minutes = time_from_record[16:18]
    seconds = time_from_record[19:21]

    # convert month name to month number
    month_name = month
    datetime_object = datetime.datetime.strptime(month_name, "%b")
    month_number = datetime_object.month
    month_number_string = str(month_number)

    print(year)
    print(month_number_string)
    print(day)
    print(hour)
    print(minutes)
    print(seconds)

    newtime = str( year + '-' + month_number_string + '-' + day + 'T' + hour + ':' + minutes + ':' + seconds + 'Z' )

    return newtime


def get_json_data(json_data):

    # Fix Time for Elasticsearch
    Time = json_data[0]['Time']
    # TimeOffset = json_data[0]['Time - Offset']
    print(Time)
    # [23/Nov/2020:07:43:07

    json_data[0]['TimeForElasticSearch'] = get_elasticsearch_time(Time)

    print("\n\n TimeForElasticSearch created from log")
    print(json_data[0]['TimeForElasticSearch'])







def get_sqs_message():
    ################################################################################################################
    #   Unpack the message from SQS and get bucket name and object name
    ################################################################################################################
    event_message = json.loads(event.Message)
    records_list = json.loads(event.Message)
    for record in records_list:
        s3_bucket_name = record['Message']['s3']['bucket']['name']
        s3_object_key = record['Message']['s3']['object']['key']
        logger.info(s3_bucket_name + ":" + s3_object_key)

        # BUCKET_NAME = 'amazon-s3-bucket-load-test-storagebucket-7el453fxmzen' # replace with your bucket name
        # KEY = '000009_20:26:20.000009_diagram.png' # replace with your object key

        s3 = boto3.resource('s3')

        ################################################################################################################
        #   Get the data from S3  
        ################################################################################################################
        try:
            s3.Bucket(s3_bucket_name).download_file(KEY, '/tmp/record.log')
            # s3.Bucket(BUCKET_NAME).download_file(KEY, '/Users/druadria/Documents/codeforwork/s3-to-elasticsearch-access-logs/record.json')
            print("Download Complete")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
            else:
                raise


def convert_and_save_json():
        ################################################################################################################
        #   Convert and Save the data from S3 in JSON format
        ################################################################################################################
        df = pd.read_csv('/tmp/record.log', sep=' ', names=[ 'Bucket Owner', 'Bucket', 'Time', 'Time - Offset', 'Remote IP', 'Requester ARN/Canonical ID','Request ID','Operation', 'Key', 'Request-URI', 'HTTP status', 'Error Code', 'Bytes Sent', 'Object Size','Total Time','Turn-Around Time', 'Referrer', 'User-Agent', 'Version Id', 'Host Id', 'Signature Version','Cipher Suite','Authentication Type', 'Host Header', 'TLS version'],usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])

        df.to_json('/tmp/record.json', orient='records')

        with open('/tmp/record.log', 'r') as f:
            json_data = json.load(f)

        # print("\n\nDISPLAY CREATED JSON FILE CONTENTS")
        # print(json_data)








################################################################################################################
################################################################################################################
#   LAMBDA HANDLER 
################################################################################################################
################################################################################################################
def lambda_handler(event, context):
    logger.info('## ENVIRONMENT VARIABLES')
    logger.info(os.environ)
    logger.info('## EVENT')
    logger.info(event)


    get_sqs_message()
    convert_and_save_json()



    

        ################################################################################################################
        #   for each object, Put records into the Firehose stream
        ################################################################################################################
        # firehose_name = firehose_name
        firehose_client = boto3.client('firehose')
        firehose_name = 's3-to-elasticsearch-accesslogs'

        json_data = get_json_data()

        print('Putting 1 record into the Firehose one at a time')
        # num_failures = 0
        for line in json_data:
            # Read a record of test data

            # logging.info(line)
            # print(line)
            # time.sleep(0.1)
            # record = {'Data': line}
            record = line
            record_string = json.dumps(record)
            encoded_record = record_string.encode("ascii")

            # Put the record into the Firehose stream
            try:
                for x in range(0, 300):
                    result = firehose_client.put_record(DeliveryStreamName=firehose_name, Record={'Data': encoded_record})
                    # time.sleep(0.1)
                    print('SUCCESS: SENDING into the Firehose one at a time')
                # num_failures = num_failures + result['FailedPutCount']
                # logging.info(f'NOT Resending {num_failures} failed records')
            except ClientError as e:
                logging.error(e)
                exit(1)


        print('COMPLETED: Putting 1 record into the Firehose one at a time')













################################################################################################################
# LOCAL TESTING and DEBUGGING  
################################################################################################################
event = {
  "Type": "Notification",
  "MessageId": "13633be1-07c9-5cfb-97fd-63f839213d0a",
  "TopicArn": "arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-cloudtrailtopicB7B8FCF0-1GS0NFTZALHZE",
  "Subject": "Amazon S3 Notification",
  "Message": "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"2020-11-01T22:54:29.962Z\",\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AWS:AROAJUND6457V5TEWWO3C:regionalDeliverySession\"},\"requestParameters\":{\"sourceIPAddress\":\"18.236.69.182\"},\"responseElements\":{\"x-amz-request-id\":\"51EA1F9F383688EB\",\"x-amz-id-2\":\"1+mvRHMgXCv5Kg72hN4TePjfmubbDZ++8mdtSdiWH495ioiwFcZsPIGryMCoXUoLd2LHez/lvJRtyUzJMioRa1okMtvAW0uo\"},\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"YjlhNTNjOTYtYWNhNi00NjgwLTk4MjctMzc5MWQzYjg0NmRi\",\"bucket\":{\"name\":\"s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\",\"ownerIdentity\":{\"principalId\":\"A316ENPQ0L9WVA\"},\"arn\":\"arn:aws:s3:::s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\"},\"object\":{\"key\":\"AWSLogs/o-2xh1murzat/696965430582/CloudTrail/us-west-2/2020/11/01/696965430582_CloudTrail_us-west-2_20201101T2250Z_V84r5ej0Vt9EciUg.json.gz\",\"size\":4110,\"eTag\":\"e20e963bef843cf2b7163ab056d103fd\",\"sequencer\":\"005F9F3CA6B68F3A51\"}}}]}",
  "Timestamp": "2020-11-01T22:54:32.259Z",
  "SignatureVersion": "1",
  "Signature": "Kca+UZACv7JDg8maASWVX1cxvAVN1bytqnD+yE3xsW0/Hgzg0/U8+BkhAp2ZNCJhOv6kXuTP0cfj3ptqB0+I9fbhfUTgV5v2YjaGA1hJnfXCT3otDeZ4VYjEqFWYVlqgh6NEbeLNHgod8hsGjbRnWNVqpQVf01KnwuTT1NTh4j2Z6ArVGErWaN07OcDF8pRmPhbnAL1SOf41tVPvK0S1fsqMESDuKPXnnoJYyDmCvgoFO02kcercXcQ1PwJxk58svQKV25S/wCXD9a4rE991mQUUJjpS/TBq6WU8hIlSMGXKvBXoz8L5YXApCLhhqVe0RN2tJNPotg9kvVz5w7LoIg==",
  "SigningCertURL": "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-a86cb10b4e1f29c941702d737128f7b6.pem",
  "UnsubscribeURL": "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-cloudtrailtopicB7B8FCF0-1GS0NFTZALHZE:f2b8ee22-4fea-4e57-b3c9-9a6f12f635cf"
}

context = "not_used"

lambda_handler(event,context)





#############################################################################################################################################################
#############################################################################################################################################################
                            #   Old code  below
#############################################################################################################################################################
#############################################################################################################################################################



        ################################################################################################################
        #   Get the data from S3  
        ################################################################################################################
        # s3_object_key = null
        # logger.info(s3_object)

        # if s3_client is None:
        #     s3_client = boto3.client("s3")

        # if not s3_object_key.endswith(".json.gz"):
        #     logger.error("S3 object key does not end with .json.gz")
        #     logger.info(s3_object_key)
        #     continue

        # s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_object_key)

        # with gzip.open(s3_obj["Body"]) as infile:
        #     records = json.load(infile)
        #     yield from records["Records"]

################################################################################################################
#   Helper function for get_secret()
################################################################################################################
def get_secret():

    secret_name = elasticcloud_secret_name
    region_name = region

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS CMK.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            


################################################################################################################
#   Get the credentials for Elasticcloud from Secrets Manager on first invocation
################################################################################################################
# secret_dictionary = get_secret()




        ################################################################################################################
        #   Loop through the items in the file from S3 
        ################################################################################################################

