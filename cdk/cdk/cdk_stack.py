from aws_cdk import core
import aws_cdk.aws_secretsmanager as aws_secretsmanager
# import aws_cdk.aws_cloudformation as aws_cloudformation
import aws_cdk.aws_lambda as aws_lambda
# from aws_cdk.core import CustomResource
import aws_cdk.aws_iam as aws_iam
import aws_cdk.aws_s3_notifications as aws_s3_notifications
import aws_cdk.aws_s3 as aws_s3
import aws_cdk.aws_sns as aws_sns
import aws_cdk.aws_sns_subscriptions as aws_sns_subscriptions
import aws_cdk.aws_sqs as aws_sqs
from aws_cdk.aws_lambda_event_sources import SqsEventSource
import aws_cdk.aws_elasticsearch as aws_elasticsearch
import aws_cdk.aws_cognito as aws_cognito
import aws_cdk.aws_apigatewayv2 as aws_apigatewayv2
import aws_cdk.aws_elasticloadbalancingv2 as aws_elasticloadbalancingv2
import aws_cdk.aws_ec2 as aws_ec2

from aws_cdk.core import CustomResource
import aws_cdk.aws_logs as logs
import aws_cdk.custom_resources as cr



class CdkStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # The code that defines your stack goes here

        ###########################################################################
        # AWS SECRETS MANAGER - Templated secret 
        ###########################################################################
        templated_secret = aws_secretsmanager.Secret(self, "TemplatedSecret",
            generate_secret_string=aws_secretsmanager.SecretStringGenerator(
                secret_string_template= "{\"username\":\"cleanbox\"}",
                generate_string_key="password"
            )
        )
        ###########################################################################
        # CUSTOM CLOUDFORMATION RESOURCE 
        ###########################################################################
        customlambda = aws_lambda.Function(self,'customconfig',
        handler='customconfig.on_event',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('customconfig'),
        )

        customlambda_statement = aws_iam.PolicyStatement(actions=["events:PutRule"], conditions=None, effect=None, not_actions=None, not_principals=None, not_resources=None, principals=None, resources=["*"], sid=None)
        customlambda.add_to_role_policy(statement=customlambda_statement)

        my_provider = cr.Provider(self, "MyProvider",
            on_event_handler=customlambda,
            # is_complete_handler=is_complete, # optional async "waiter"
            log_retention=logs.RetentionDays.SIX_MONTHS
        )

        CustomResource(self, 'customconfigresource', service_token=my_provider.service_token)


        ###########################################################################
        # AWS LAMBDA FUNCTIONS 
        ###########################################################################
        sqs_to_elastic_cloud_lambda_access_logs = aws_lambda.Function(self,'sqs_to_elastic_cloud_lambda_access_logs',
        handler='sqs_to_elastic_cloud_lambda_access_logs.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elastic_cloud_lambda_access_logs'),
        )

        sqs_to_elastic_cloud_lambda_cloudtrail = aws_lambda.Function(self,'sqs_to_elastic_cloud_lambda_cloudtrail',
        handler='sqs_to_elastic_cloud_lambda_cloudtrail.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elastic_cloud_lambda_cloudtrail'),
        )

        sqs_to_elastic_search_lambda_access_logs = aws_lambda.Function(self,'sqs_to_elastic_search_lambda_access_logs',
        handler='sqs_to_elastic_search_lambda_access_logs.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elastic_search_lambda_access_logs'),
        )

        sqs_to_elastic_search_lambda_cloudtrail = aws_lambda.Function(self,'sqs_to_elastic_search_lambda_cloudtrail',
        handler='sqs_to_elastic_search_lambda_cloudtrail.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elastic_search_lambda_cloudtrail'),
        )
        sqs_to_elastic_search_lambda_cloudtrail.add_environment("ES_ENDPOINT", "-")
        sqs_to_elastic_search_lambda_cloudtrail.add_environment("index_name", "-")
        sqs_to_elastic_search_lambda_cloudtrail.add_environment("ES_DOC_TYPE", "cloudtrail")




        ###########################################################################
        # AMAZON S3 BUCKETS 
        ###########################################################################
        access_log_bucket = aws_s3.Bucket(self, "access_log_bucket")
        cloudtrail_bucket = aws_s3.Bucket(self, "cloudtrail_bucket")


        ###########################################################################
        # AWS SNS TOPICS 
        ###########################################################################
        access_log_topic = aws_sns.Topic(self, "access_log_topic")
        cloudtrail_topic = aws_sns.Topic(self, "cloudtrail_topic")


        ###########################################################################
        # ADD AMAZON S3 BUCKET NOTIFICATIONS
        ###########################################################################
        access_log_bucket.add_event_notification(aws_s3.EventType.OBJECT_CREATED, aws_s3_notifications.SnsDestination(access_log_topic))
        cloudtrail_bucket.add_event_notification(aws_s3.EventType.OBJECT_CREATED, aws_s3_notifications.SnsDestination(cloudtrail_topic))


        ###########################################################################
        # AWS SQS QUEUES
        ###########################################################################
        sqs_to_elastic_cloud_lambda_access_logs_queue = aws_sqs.Queue(self, "sqs_to_elastic_cloud_lambda_access_logs_queue")

        sqs_to_elastic_cloud_lambda_cloudtrail_queue = aws_sqs.Queue(self, "sqs_to_elastic_cloud_lambda_cloudtrail_queue")

        sqs_to_elastic_search_lambda_access_logs_queue = aws_sqs.Queue(self, "sqs_to_elastic_search_lambda_access_logs_queue")

        sqs_to_elastic_search_lambda_cloudtrail_queue = aws_sqs.Queue(self, "sqs_to_elastic_search_lambda_cloudtrail_queue")


        ###########################################################################
        # AWS SNS TOPIC SUBSCRIPTIONS
        ###########################################################################
        access_log_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elastic_cloud_lambda_access_logs_queue))
        access_log_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elastic_search_lambda_access_logs_queue))

        cloudtrail_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elastic_cloud_lambda_cloudtrail_queue))
        cloudtrail_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elastic_search_lambda_cloudtrail_queue))

        
        ###########################################################################
        # AWS LAMBDA SQS EVENT SOURCE
        ###########################################################################
        sqs_to_elastic_cloud_lambda_access_logs.add_event_source(SqsEventSource(sqs_to_elastic_cloud_lambda_access_logs_queue,batch_size=10))
        sqs_to_elastic_cloud_lambda_cloudtrail.add_event_source(SqsEventSource(sqs_to_elastic_cloud_lambda_cloudtrail_queue,batch_size=10))
        sqs_to_elastic_search_lambda_access_logs.add_event_source(SqsEventSource(sqs_to_elastic_search_lambda_access_logs_queue,batch_size=10))
        sqs_to_elastic_search_lambda_cloudtrail.add_event_source(SqsEventSource(sqs_to_elastic_search_lambda_cloudtrail_queue,batch_size=10))


        ###########################################################################
        # AWS ELASTICSEARCH DOMAIN
        ###########################################################################
        s3_to_elasticsearch_domain = aws_elasticsearch.Domain(self, "s3-to-elasticsearch",
            version=aws_elasticsearch.ElasticsearchVersion.V7_1,
            capacity={
                "master_nodes": 3,
                "data_nodes": 4
            },
            ebs={
                "volume_size": 100
            },
            zone_awareness={
                "availability_zone_count": 2
            },
            logging={
                "slow_search_log_enabled": True,
                "app_log_enabled": True,
                "slow_index_log_enabled": True
            }
        )


        ###########################################################################
        # AMAZON COGNITO USER POOL
        ###########################################################################
        s3_to_elasticsearch_user_pool = aws_cognito.UserPool(self, "s3-to-elasticsearch-pool",
                                                            account_recovery=None, 
                                                            auto_verify=None, 
                                                            custom_attributes=None, 
                                                            email_settings=None, 
                                                            enable_sms_role=None, 
                                                            lambda_triggers=None, 
                                                            mfa=None, 
                                                            mfa_second_factor=None, 
                                                            password_policy=None, 
                                                            self_sign_up_enabled=None, 
                                                            sign_in_aliases=aws_cognito.SignInAliases(email=True, phone=None, preferred_username=None, username=True), 
                                                            sign_in_case_sensitive=None, 
                                                            sms_role=None, 
                                                            sms_role_external_id=None, 
                                                            standard_attributes=None, 
                                                            user_invitation=None, 
                                                            user_pool_name=None, 
                                                            user_verification=None
                                                            )

