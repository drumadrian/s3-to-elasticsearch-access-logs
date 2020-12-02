from __future__ import print_function
from botocore.exceptions import ClientError
import datetime as datetime
import pandas as pd
import botocore
import logging
import boto3
import base64
import gzip
import time
import json
import io
import csv
import os




################################################################################################################
#   References
################################################################################################################
# https://stackoverflow.com/questions/37703634/how-to-import-a-text-file-on-aws-s3-into-pandas-without-writing-to-disk
# https://docs.aws.amazon.com/AmazonS3/latest/dev/notification-content-structure.html



################################################################################################################
#   Config
################################################################################################################
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_ID']
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_USERNAME']
# elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_PASSWORD']
# logger = logging.getLogger()
# logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)
# local_event = {"Messages": [{"MessageId": "d7c42a19-d145-4511-90c5-f03d9a440f0a", "ReceiptHandle": "AQEBCzWbUdLHaPvIaHsTn/qlRHf5b31v4joEkK8vk8a6yZcC5t6PFZOwiGBX87e2AzLshceHxvgeezyumfxsqr9jrRlN4c+lbPSwqgpxHd/8MoMY184ygLMHO5hDSxC2H/kqdytmXLXlDQGvMg0Wpk05s8JRgqABeZqp45u6vw2jjg6zn4LpAqp7PbCjkezRKLRXG6MLyu6bntAVRQW8A15XxAItdYwesYtaqW5CH7Fwql5m9/DU11ng8uFpNedqVeScXr05BFA0NNgjma8NAjjPx04LdjSijs/7jPVvStrgrDOTLx1reTWiiHSp8rY8Sr901bh+Eg6n6Ur2GfRrGfSXrbiCzEJ0quANrC1MfSzw5XlUZP9a4iaNZsrEIoie+rKk3tE1haU+LJDKFQkb6mDv+SRVGRCwDd9cli3kZiBDvPEerG731nKmJ5g+OTTHLKnqcWLWbwAcZY9vKgBY0btN87ytp6Kgas6FgSiy4nmX+08=", "MD5OfBody": "d9715be551a977168000acd973a8072d", "Body": "{\n  \"Type\" : \"Notification\",\n  \"MessageId\" : \"f952167c-e75f-5371-b2dc-4e476c7f9027\",\n  \"TopicArn\" : \"arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-access-logs-accesslogtopic6A6F66D7-1CVZECE32AT4M\",\n  \"Subject\" : \"Amazon S3 Notification\",\n  \"Message\" : \"{\\\"Records\\\":[{\\\"eventVersion\\\":\\\"2.1\\\",\\\"eventSource\\\":\\\"aws:s3\\\",\\\"awsRegion\\\":\\\"us-west-2\\\",\\\"eventTime\\\":\\\"2020-11-27T23:16:47.489Z\\\",\\\"eventName\\\":\\\"ObjectCreated:Put\\\",\\\"userIdentity\\\":{\\\"principalId\\\":\\\"A2HRK4T7OWQKNJ\\\"},\\\"requestParameters\\\":{\\\"sourceIPAddress\\\":\\\"172.16.120.122\\\"},\\\"responseElements\\\":{\\\"x-amz-request-id\\\":\\\"950C0A33F57DF771\\\",\\\"x-amz-id-2\\\":\\\"SKd42p7jsiL+doA2Qz8B3gYtE8lCT8kkol67jBCl3+40ltnzOVNMCX2JLXdv4ET8e1KlCmTN/n4QgjYZn72XTg5HWQf92pQh\\\"},\\\"s3\\\":{\\\"s3SchemaVersion\\\":\\\"1.0\\\",\\\"configurationId\\\":\\\"NTY3YTQ4NWItMDVmOS00MTA2LTg4OTgtOWFmZTEwODllMzRj\\\",\\\"bucket\\\":{\\\"name\\\":\\\"s3-to-elasticsearch-acces-accesslogbucket5c1457b7-151mo29j9uf83\\\",\\\"ownerIdentity\\\":{\\\"principalId\\\":\\\"A316ENPQ0L9WVA\\\"},\\\"arn\\\":\\\"arn:aws:s3:::s3-to-elasticsearch-acces-accesslogbucket5c1457b7-151mo29j9uf83\\\"},\\\"object\\\":{\\\"key\\\":\\\"2020-11-27-23-16-48-08AB4BC89388039F\\\",\\\"size\\\":3092,\\\"eTag\\\":\\\"6f24045964158499b97615447dce0710\\\",\\\"sequencer\\\":\\\"005FC188E0308AA05A\\\"}}}]}\",\n  \"Timestamp\" : \"2020-11-27T23:16:48.770Z\",\n  \"SignatureVersion\" : \"1\",\n  \"Signature\" : \"fxmieXOR3/1YJJMhfGw/RVr/XREAuc6rlCd+7jOqIJwhUSSDSIJC+Tqlbbmvw9NDn1y1m3XW0VpiY+xWUGgWujJm5xb6zGIXlU9+g50rGVhX/UpSbEPB4q5gOZzaL+vKbyB2LVDSI8Q631fKz7uaBLbAbWJoF3ZjNfzaFT76R32RgxKoLzQl1QRuT0GjiSCCW6y/N5FHc5fOngdn1R166raQP0kJojvGglR/dPmGtJi2pIUpXlxMJnf/YCs+4FsvcNNNuGa2xASuFVLZ77puViNQXTC6wbLg3YJmfAFYd8YqEkjWVnBauFtlnSRMIinyl5EpNso4s0TdY6BmSZnYzQ==\",\n  \"SigningCertURL\" : \"https://sns.us-west-2.amazonaws.com/SimpleNotificationService-010a507c1833636cd94bdb98bd93083a.pem\",\n  \"UnsubscribeURL\" : \"https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-access-logs-accesslogtopic6A6F66D7-1CVZECE32AT4M:3e906df4-be15-4b1c-a98f-48086fb5f63b\"\n}"}], "ResponseMetadata": {"RequestId": "569d7114-2050-56b2-b4e6-292fac8af0b7", "HTTPStatusCode": 200, "HTTPHeaders": {"x-amzn-requestid": "569d7114-2050-56b2-b4e6-292fac8af0b7", "date": "Fri, 27 Nov 2020 23:24:10 GMT", "content-type": "text/xml", "content-length": "3607"}, "RetryAttempts": 0}}


region = os.environ['AWS_REGION']
firehose_name = os.environ['FIREHOSE_NAME']
QUEUEURL = os.environ['QUEUEURL']
file_path = '/tmp/record.json'
sqs_client = boto3.client('sqs')
s3_client = boto3.resource('s3')
firehose_client = boto3.client('firehose')
context = "not_used"

################################################################################################################
#   Config
################################################################################################################




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

    print("\n\nTimeForElasticSearch created from log")
    print(json_data[0]['TimeForElasticSearch'])
    return json_data


def get_sqs_message(QUEUEURL, sqs_client):
    ###### Example of string data that was sent:#########
    # payload = { 
    # "bucketname": bucketname, 
    # "s3_file_name": s3_file_name
    # }
    ################################################

    receive_message_response = dict()
    while 'Messages' not in receive_message_response:
        receive_message_response = sqs_client.receive_message(
            QueueUrl=QUEUEURL,
            # AttributeNames=[
            #     'All'|'Policy'|'VisibilityTimeout'|'MaximumMessageSize'|'MessageRetentionPeriod'|'ApproximateNumberOfMessages'|'ApproximateNumberOfMessagesNotVisible'|'CreatedTimestamp'|'LastModifiedTimestamp'|'QueueArn'|'ApproximateNumberOfMessagesDelayed'|'DelaySeconds'|'ReceiveMessageWaitTimeSeconds'|'RedrivePolicy'|'FifoQueue'|'ContentBasedDeduplication'|'KmsMasterKeyId'|'KmsDataKeyReusePeriodSeconds',
            # ],
            # MessageAttributeNames=[
            #     'string',
            # ],
            MaxNumberOfMessages=1
            # VisibilityTimeout=123,
            # WaitTimeSeconds=123,
            # ReceiveRequestAttemptId='string'
        )
        if 'Messages' in receive_message_response:
            number_of_messages = len(receive_message_response['Messages'])
            print("\n received {0} messages!! ....Processing message \n".format(number_of_messages))
            break
        else:
            print("\n received 0 messages!! waiting.....5 seconds before retrying \n")
            time.sleep(5)
            continue
        

    ReceiptHandle = receive_message_response['Messages'][0]['ReceiptHandle']
    delete_message_response = sqs_client.delete_message(
    QueueUrl=QUEUEURL,
    ReceiptHandle=ReceiptHandle
    )
    print("delete_message_response = {0}".format(delete_message_response))
    return receive_message_response







def process_sqs_message(event):
    ################################################################################################################
    #   Unpack the message from SQS and get bucket name and object name
    ################################################################################################################
    # event_messages = json.loads(event)
    # Messages = json.loads(event_messages['Messages'])
    Messages = event['Messages']
    for message in Messages:
        print("\nmessage = {0}".format(message))
        print("\ntype(message) = {0}\n".format(type(message)))

        message_body = message['Body']
        print("\nmessage_body = {0}".format(message_body))
        print("\ntype(message_body) = {0}\n".format(type(message_body)))

        message_body_dict = json.loads(message_body)
        print("\nmessage_body_dict = {0}".format(message_body_dict))
        print("\ntype(message_body_dict) = {0}\n".format(type(message_body_dict)))

        message_within_message_body_str = message_body_dict['Message']
        print("\nmessage_within_message_body_str = {0}".format(message_within_message_body_str))
        print("\ntype(message_within_message_body_str) = {0}\n".format(type(message_within_message_body_str)))

        message_within_message_body = json.loads(message_within_message_body_str)
        print("\nmessage_within_message_body = {0}".format(message_within_message_body))
        print("\ntype(message_within_message_body) = {0}\n".format(type(message_within_message_body)))

        s3_notification_records = message_within_message_body['Records']

        print("\ns3_notification_records = {0}".format(s3_notification_records))

        s3_bucket_name = s3_notification_records[0]['s3']['bucket']['name']
        s3_object_key = s3_notification_records[0]['s3']['object']['key']
        print(s3_bucket_name + ":" + s3_object_key)

        # BUCKET_NAME = 'amazon-s3-bucket-load-test-storagebucket-7el453fxmzen' # replace with your bucket name
        # KEY = '000009_20:26:20.000009_diagram.png' # replace with your object key

        ################################################################################################################
        #   Get the data from S3  
        ################################################################################################################
        try:
            s3_client.Bucket(s3_bucket_name).download_file(s3_object_key, file_path)
            # s3_client.Bucket(BUCKET_NAME).download_file(KEY, '/Users/druadria/Documents/codeforwork/s3-to-elasticsearch-access-logs/record.json')
            print("\n S3 File Download: COMPLETE\n")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == "404":
                print("The object does not exist.")
            else:
                raise


def convert_and_save_json():
    ################################################################################################################
    #   Convert and Save the data from S3 in JSON format
    ################################################################################################################
    df = pd.read_csv(file_path, sep=' ', names=[ 'Bucket Owner', 'Bucket', 'Time', 'Time - Offset', 'Remote IP', 'Requester ARN/Canonical ID','Request ID','Operation', 'Key', 'Request-URI', 'HTTP status', 'Error Code', 'Bytes Sent', 'Object Size','Total Time','Turn-Around Time', 'Referrer', 'User-Agent', 'Version Id', 'Host Id', 'Signature Version','Cipher Suite','Authentication Type', 'Host Header', 'TLS version'],usecols=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])

    df.to_json(file_path, orient='records')

    with open(file_path, 'r') as f:
        json_data = json.load(f)

    print("\n\nDISPLAY CREATED JSON FILE CONTENTS")
    print(json_data)

    return json_data

def put_object_in_kinesis_firehose_stream(json_data_from_local_file):
    ################################################################################################################
    #   for each object, Put records into the Firehose stream
    ################################################################################################################
    # firehose_name = firehose_name

    json_data_list = get_json_data(json_data_from_local_file)
    json_data = json_data_list[0]

    print('Putting 1 record into the Firehose one at a time\n')
    print("\njson_data = {0}".format(json_data))
    print("\ntype(json_data) = {0}\n".format(type(json_data)))
    # num_failures = 0
    # for line in json_data:
        # Read a record of test data

        # logging.info(line)
        # print(line)
        # time.sleep(0.1)
        # record = {'Data': line}
        # record = line
    record = json_data
    record_string = json.dumps(record)
    encoded_record = record_string.encode("ascii")

    # Put the record into the Firehose stream
    try:
        result = firehose_client.put_record(DeliveryStreamName=firehose_name, Record={'Data': encoded_record})
        # time.sleep(0.1)
        print('\nSUCCESS: SENDING into the Firehose one at a time')
    except ClientError as e:
        print('\nFAILED: SENDING into the Firehose one at a time\n')
        print(e)
        exit(1)



    print('COMPLETED: Putting 1 record into the Firehose one at a time')



################################################################################################################
################################################################################################################
#   LAMBDA HANDLER 
################################################################################################################
################################################################################################################
def lambda_handler(event, context):
    # logger.info('## ENVIRONMENT VARIABLES')
    # logger.info(os.environ)
    # logger.info('## EVENT')
    # logger.info(event)

    process_sqs_message(event)
    json_data_from_local_file = convert_and_save_json()
    put_object_in_kinesis_firehose_stream(json_data_from_local_file)

################################################################################################################
################################################################################################################
#   LAMBDA HANDLER 
################################################################################################################
################################################################################################################



################################################################################################################
# LOCAL TESTING and DEBUGGING  
################################################################################################################

# for x in range(0, 300):
while True:
    event = get_sqs_message(QUEUEURL, sqs_client)
    print("\n event={0}\n".format(json.dumps(event)))
    lambda_handler(event,context)















