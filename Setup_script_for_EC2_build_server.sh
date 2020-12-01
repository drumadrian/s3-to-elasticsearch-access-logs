# Setup script for EC2 build server



################################################################################################################
# REFERENCES 
################################################################################################################
# https://www.hostinger.com/tutorials/how-to-install-and-use-linux-screen/
# https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/eb-cli3-install-linux.html
# https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/setting-up-node-on-ec2-instance.html


################################################################################################################
#   Update the Operating System packages and install tools
################################################################################################################
sudo yum update -y

sudo yum install -y git

curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash

. ~/.nvm/nvm.sh

nvm install node

node -e "console.log('Running Node.js ' + process.version)"

# sudo yum install -y screen

sudo yum install -y python37

# curl -O https://bootstrap.pypa.io/get-pip.py

# python3 get-pip.py

git clone https://github.com/drumadrian/s3-to-elasticsearch-access-logs.git

cd s3-to-elasticsearch-access-logs

pip install -r requirements.txt 

export AWS_REGION='us-west-2'
export FIREHOSE_NAME='s3-to-elasticsearch-accesslogs3'
export QUEUEURL='https://sqs.us-west-2.amazonaws.com/696965430582/s3-to-elasticsearch-access-logs-sqstoelasticsearchservicequeueC036-1B9QNWKG9JSRA'

cd s3-to-elasticsearch-access-logs
python3 sqs_to_elasticsearch_service/sqs_to_elasticsearch_service_EC2.py







