from __future__ import print_function
import os
import logging
import boto3
import base64
from botocore.exceptions import ClientError
import gzip
import json



region = os.environ['AWS_REGION']
elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_ID']
elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_USERNAME']
elasticcloud_secret_name = os.environ['ELASTIC_CLOUD_PASSWORD']
logger = logging.getLogger()
# logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)





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
            
    # Your code goes here.  





################################################################################################################
#   Get the credentials for Elasticcloud from Secrets Manager on first invocation
################################################################################################################
secret_dictionary = get_secret()







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
    logger.info("it worked, you can sleep now")




    ################################################################################################################
    #   Unpack the message from SQS and get object 
    ################################################################################################################

    event_message = json.loads(event.Message)
    records_list = json.loads(event.Message)
    for record in records_list:
        s3_bucket_name = record['Message']['s3']['bucket']['name']
        s3_object_key = record['Message']['s3']['object']['key']
        logger.info(s3_bucket_name + ":" + s3_object_key)

        # exit()

        ################################################################################################################
        #   Get the data from S3  
        ################################################################################################################
        s3_object_key = null
        logger.info(s3_object)

        if s3_client is None:
            s3_client = boto3.client("s3")

        if not s3_object_key.endswith(".json.gz"):
            logger.error("S3 object key does not end with .json.gz")
            logger.info(s3_object_key)
            continue

        s3_obj = s3_client.get_object(Bucket=bucket, Key=s3_object_key)

        with gzip.open(s3_obj["Body"]) as infile:
            records = json.load(infile)
            yield from records["Records"]


        ################################################################################################################
        #   Loop through the items in the file from S3 
        ################################################################################################################




        ################################################################################################################
        #   for each object, create the index name for writing to Elasticsearch
        ################################################################################################################




        ################################################################################################################
        #   for each object, write data to Elasticsearch using the correct index name
        ################################################################################################################
























################################################################################################################
# LOCAL TESTING and DEBUGGING  
################################################################################################################

# example event in lambda invocation
# {
#   "Type": "Notification",
#   "MessageId": "13633be1-07c9-5cfb-97fd-63f839213d0a",
#   "TopicArn": "arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-cloudtrailtopicB7B8FCF0-1GS0NFTZALHZE",
#   "Subject": "Amazon S3 Notification",
#   "Message": "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"2020-11-01T22:54:29.962Z\",\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AWS:AROAJUND6457V5TEWWO3C:regionalDeliverySession\"},\"requestParameters\":{\"sourceIPAddress\":\"18.236.69.182\"},\"responseElements\":{\"x-amz-request-id\":\"51EA1F9F383688EB\",\"x-amz-id-2\":\"1+mvRHMgXCv5Kg72hN4TePjfmubbDZ++8mdtSdiWH495ioiwFcZsPIGryMCoXUoLd2LHez/lvJRtyUzJMioRa1okMtvAW0uo\"},\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"YjlhNTNjOTYtYWNhNi00NjgwLTk4MjctMzc5MWQzYjg0NmRi\",\"bucket\":{\"name\":\"s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\",\"ownerIdentity\":{\"principalId\":\"A316ENPQ0L9WVA\"},\"arn\":\"arn:aws:s3:::s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\"},\"object\":{\"key\":\"AWSLogs/o-2xh1murzat/696965430582/CloudTrail/us-west-2/2020/11/01/696965430582_CloudTrail_us-west-2_20201101T2250Z_V84r5ej0Vt9EciUg.json.gz\",\"size\":4110,\"eTag\":\"e20e963bef843cf2b7163ab056d103fd\",\"sequencer\":\"005F9F3CA6B68F3A51\"}}}]}",
#   "Timestamp": "2020-11-01T22:54:32.259Z",
#   "SignatureVersion": "1",
#   "Signature": "Kca+UZACv7JDg8maASWVX1cxvAVN1bytqnD+yE3xsW0/Hgzg0/U8+BkhAp2ZNCJhOv6kXuTP0cfj3ptqB0+I9fbhfUTgV5v2YjaGA1hJnfXCT3otDeZ4VYjEqFWYVlqgh6NEbeLNHgod8hsGjbRnWNVqpQVf01KnwuTT1NTh4j2Z6ArVGErWaN07OcDF8pRmPhbnAL1SOf41tVPvK0S1fsqMESDuKPXnnoJYyDmCvgoFO02kcercXcQ1PwJxk58svQKV25S/wCXD9a4rE991mQUUJjpS/TBq6WU8hIlSMGXKvBXoz8L5YXApCLhhqVe0RN2tJNPotg9kvVz5w7LoIg==",
#   "SigningCertURL": "https://sns.us-west-2.amazonaws.com/SimpleNotificationService-a86cb10b4e1f29c941702d737128f7b6.pem",
#   "UnsubscribeURL": "https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:696965430582:s3-to-elasticsearch-cloudtrailtopicB7B8FCF0-1GS0NFTZALHZE:f2b8ee22-4fea-4e57-b3c9-9a6f12f635cf"
# }


# {\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"aws:s3\",\"awsRegion\":\"us-west-2\",\"eventTime\":\"2020-11-01T22:54:29.962Z\",\"eventName\":\"ObjectCreated:Put\",\"userIdentity\":{\"principalId\":\"AWS:AROAJUND6457V5TEWWO3C:regionalDeliverySession\"},\"requestParameters\":{\"sourceIPAddress\":\"18.236.69.182\"},\"responseElements\":{\"x-amz-request-id\":\"51EA1F9F383688EB\",\"x-amz-id-2\":\"1+mvRHMgXCv5Kg72hN4TePjfmubbDZ++8mdtSdiWH495ioiwFcZsPIGryMCoXUoLd2LHez/lvJRtyUzJMioRa1okMtvAW0uo\"},\"s3\":{\"s3SchemaVersion\":\"1.0\",\"configurationId\":\"YjlhNTNjOTYtYWNhNi00NjgwLTk4MjctMzc5MWQzYjg0NmRi\",\"bucket\":{\"name\":\"s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\",\"ownerIdentity\":{\"principalId\":\"A316ENPQ0L9WVA\"},\"arn\":\"arn:aws:s3:::s3-to-elasticsearch-cloudtrailbucket651b1cf1-1sxwk9yev080b\"},\"object\":{\"key\":\"AWSLogs/o-2xh1murzat/696965430582/CloudTrail/us-west-2/2020/11/01/696965430582_CloudTrail_us-west-2_20201101T2250Z_V84r5ej0Vt9EciUg.json.gz\",\"size\":4110,\"eTag\":\"e20e963bef843cf2b7163ab056d103fd\",\"sequencer\":\"005F9F3CA6B68F3A51\"}}}]}



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



