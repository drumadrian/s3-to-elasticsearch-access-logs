# Setup script for EC2 



################################################################################################################
# REFERENCES 
################################################################################################################
# https://www.hostinger.com/tutorials/how-to-install-and-use-linux-screen/



################################################################################################################
#   Update the Operating System packages and install tools
################################################################################################################
sudo yum update -y

sudo yum install -y screen

git clone https://github.com/drumadrian/s3-to-elasticsearch-access-logs.git

cd s3-to-elasticsearch-access-logs

pip3 install -r requirements.txt 

export AWS_REGION='us-west-2'
export FIREHOSE_NAME='s3-to-elasticsearch-accesslogs3'
export QUEUEURL='https://sqs.us-west-2.amazonaws.com/696965430582/s3-to-elasticsearch-access-logs-sqstoelasticsearchservicequeueC036-1B9QNWKG9JSRA'

cd s3-to-elasticsearch-access-logs
python3 cdk/sqs_to_elasticsearch_service/sqs_to_elasticsearch_service_EC2.py







