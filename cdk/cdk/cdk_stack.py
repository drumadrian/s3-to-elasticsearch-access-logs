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
import aws_cdk.aws_elasticloadbalancingv2 as aws_elasticloadbalancingv2
import aws_cdk.aws_ec2 as aws_ec2
import aws_cdk.aws_logs as logs
import aws_cdk.aws_kinesisfirehose as aws_kinesisfirehose
import inspect as inspect

# import jsii
# from ._jsii import *
# from typing import Union
# from typing import Union, Any, List, Optional, cast

# from aws_cdk.core import CustomResource
# import aws_cdk.custom_resources as cr
# import aws_cdk.aws_apigatewayv2 as aws_apigatewayv2


###########################################################################
# References 
###########################################################################
# https://github.com/aws/aws-cdk/issues/7236



class CdkStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)

        # The code that defines your stack goes here

        ###########################################################################
        # AWS SECRETS MANAGER - Templated secret 
        ###########################################################################
        # templated_secret = aws_secretsmanager.Secret(self, "TemplatedSecret",
        #     generate_secret_string=aws_secretsmanager.SecretStringGenerator(
        #         secret_string_template= "{\"username\":\"cleanbox\"}",
        #         generate_string_key="password"
        #     )
        # )
        ###########################################################################
        # CUSTOM CLOUDFORMATION RESOURCE 
        ###########################################################################
        # customlambda = aws_lambda.Function(self,'customconfig',
        # handler='customconfig.on_event',
        # runtime=aws_lambda.Runtime.PYTHON_3_7,
        # code=aws_lambda.Code.asset('customconfig'),
        # )

        # customlambda_statement = aws_iam.PolicyStatement(actions=["events:PutRule"], conditions=None, effect=None, not_actions=None, not_principals=None, not_resources=None, principals=None, resources=["*"], sid=None)
        # customlambda.add_to_role_policy(statement=customlambda_statement)

        # my_provider = cr.Provider(self, "MyProvider",
        #     on_event_handler=customlambda,
        #     # is_complete_handler=is_complete, # optional async "waiter"
        #     log_retention=logs.RetentionDays.SIX_MONTHS
        # )

        # CustomResource(self, 'customconfigresource', service_token=my_provider.service_token)


        ###########################################################################
        # AWS LAMBDA FUNCTIONS 
        ###########################################################################
        sqs_to_elastic_cloud = aws_lambda.Function(self,'sqs_to_elastic_cloud',
        handler='sqs_to_elastic_cloud.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elastic_cloud'),
        memory_size=4096,
        timeout=core.Duration.seconds(300),
        log_retention=logs.RetentionDays.ONE_DAY
        )

        sqs_to_elasticsearch_service = aws_lambda.Function(self,'sqs_to_elasticsearch_service',
        handler='sqs_to_elasticsearch_service.lambda_handler',
        runtime=aws_lambda.Runtime.PYTHON_3_7,
        code=aws_lambda.Code.asset('sqs_to_elasticsearch_service'),
        memory_size=4096,
        timeout=core.Duration.seconds(300),
        log_retention=logs.RetentionDays.ONE_DAY
        )

        # sqs_to_elasticsearch_service.add_environment("kinesis_firehose_name", "-")
        # sqs_to_elastic_cloud.add_environment("index_name", "-")

        ###########################################################################
        # AWS LAMBDA FUNCTIONS 
        ###########################################################################
        # sqs_to_elasticsearch_service_permission = aws_lambda.Permission(*, principal, action=None, event_source_token=None, scope=None, source_account=None, source_arn=None)

        ###########################################################################
        # AMAZON S3 BUCKETS 
        ###########################################################################
        access_log_bucket = aws_s3.Bucket(self, "access_log_bucket")
        kinesis_log_bucket = aws_s3.Bucket(self, "kinesis_log_bucket")


        ###########################################################################
        # LAMBDA SUPPLEMENTAL POLICIES 
        ###########################################################################
        lambda_supplemental_policy_statement = aws_iam.PolicyStatement(
            effect=aws_iam.Effect.ALLOW,
            actions=["s3:Get*","s3:Head*","s3:List*","firehose:*"],
            resources=["*"]
            )

        sqs_to_elastic_cloud.add_to_role_policy(lambda_supplemental_policy_statement)
        sqs_to_elasticsearch_service.add_to_role_policy(lambda_supplemental_policy_statement)
        ###########################################################################
        # AWS SNS TOPICS 
        ###########################################################################
        access_log_topic = aws_sns.Topic(self, "access_log_topic")


        ###########################################################################
        # ADD AMAZON S3 BUCKET NOTIFICATIONS
        ###########################################################################
        access_log_bucket.add_event_notification(aws_s3.EventType.OBJECT_CREATED, aws_s3_notifications.SnsDestination(access_log_topic))


        ###########################################################################
        # AWS SQS QUEUES
        ###########################################################################
        sqs_to_elasticsearch_service_queue_iqueue = aws_sqs.Queue(self, "sqs_to_elasticsearch_service_queue_dlq")
        sqs_to_elasticsearch_service_queue_dlq = aws_sqs.DeadLetterQueue(max_receive_count=10, queue=sqs_to_elasticsearch_service_queue_iqueue)
        sqs_to_elasticsearch_service_queue = aws_sqs.Queue(self, "sqs_to_elasticsearch_service_queue", visibility_timeout=core.Duration.seconds(301), dead_letter_queue=sqs_to_elasticsearch_service_queue_dlq)

        sqs_to_elastic_cloud_queue_iqueue = aws_sqs.Queue(self, "sqs_to_elastic_cloud_queue_dlq")
        sqs_to_elastic_cloud_queue_dlq = aws_sqs.DeadLetterQueue(max_receive_count=10, queue=sqs_to_elastic_cloud_queue_iqueue)
        sqs_to_elastic_cloud_queue = aws_sqs.Queue(self, "sqs_to_elastic_cloud_queue", visibility_timeout=core.Duration.seconds(301), dead_letter_queue=sqs_to_elastic_cloud_queue_dlq)


        ###########################################################################
        # AWS SNS TOPIC SUBSCRIPTIONS
        ###########################################################################
        access_log_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elastic_cloud_queue))
        access_log_topic.add_subscription(aws_sns_subscriptions.SqsSubscription(sqs_to_elasticsearch_service_queue))

        
        ###########################################################################
        # AWS LAMBDA SQS EVENT SOURCE
        ###########################################################################
        sqs_to_elastic_cloud.add_event_source(SqsEventSource(sqs_to_elastic_cloud_queue,batch_size=10))
        sqs_to_elasticsearch_service.add_event_source(SqsEventSource(sqs_to_elasticsearch_service_queue,batch_size=10))


        ###########################################################################
        # AWS ELASTICSEARCH DOMAIN
        ###########################################################################

        ###########################################################################
        # AWS ELASTICSEARCH DOMAIN ACCESS POLICY 
        ###########################################################################
        this_aws_account = aws_iam.AccountPrincipal(account_id="012345678912")
        # s3_to_elasticsearch_access_logs_domain_access_policy_statement = aws_iam.PolicyStatement(
        #     principals=[this_aws_account],
        #     effect=aws_iam.Effect.ALLOW,
        #     actions=["es:*"],
        #     resources=["*"]
        #     )
        # s3_to_elasticsearch_access_logs_domain_access_policy_statement_list=[]
        # s3_to_elasticsearch_access_logs_domain_access_policy_statement_list.append(s3_to_elasticsearch_access_logs_domain_access_policy_statement)

        s3_to_elasticsearch_access_logs_domain = aws_elasticsearch.Domain(self, "s3-to-elasticsearch-access-logs-domain",
            # access_policies=s3_to_elasticsearch_access_logs_domain_access_policy_statement_list,
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
        s3_to_elasticsearch_user_pool = aws_cognito.UserPool(self, "s3-to-elasticsearch-access-logs-pool",
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


        ###########################################################################
        # AMAZON KINESIS FIREHOSE STREAM
        ###########################################################################
        # kinesis_policy_statement = aws_iam.PolicyStatement(
        #     effect=aws_iam.Effect.ALLOW,
        #     # actions=["es:*", "s3:*", "kms:*", "kinesis:*", "lambda:*"],
        #     actions=["*"],
        #     resources=["*"]
        #     )

        # kinesis_policy_document = aws_iam.PolicyDocument()
        # kinesis_policy_document.add_statements(kinesis_policy_statement)

        kinesis_firehose_stream_role = aws_iam.Role( self, 
            "BaseVPCIAMLogRole", 
            assumed_by=aws_iam.ServicePrincipal('firehose.amazonaws.com'), 
            role_name=None, 
            inline_policies={ 
                "AllowLogAccess": aws_iam.PolicyDocument( assign_sids=False, 
                    statements=[ 
                        aws_iam.PolicyStatement( 
                            actions=[ '*', 'es:*', 'logs:PutLogEvents', 'logs:DescribeLogGroups', 'logs:DescribeLogsStreams' ], 
                            effect=aws_iam.Effect('ALLOW'), 
                            resources=['*'] 
                        ) 
                    ] 
                ) 
            } 
        )        
        
        RetryOptions = aws_kinesisfirehose.CfnDeliveryStream.ElasticsearchRetryOptionsProperty(duration_in_seconds=300)
        s3_configuration = aws_kinesisfirehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
            bucket_arn=kinesis_log_bucket.bucket_arn,
            role_arn = kinesis_firehose_stream_role.role_arn)

        ElasticsearchDestinationConfiguration = aws_kinesisfirehose.CfnDeliveryStream.ElasticsearchDestinationConfigurationProperty(
            # "BufferingHints" : ElasticsearchBufferingHints,
            # "CloudWatchLoggingOptions" : CloudWatchLoggingOptions,
            # "ClusterEndpoint" : String,
            domain_arn = s3_to_elasticsearch_access_logs_domain.domain_arn,
            index_name = "s3-to-elasticsearch-accesslogs",
            index_rotation_period = "OneDay",
            # "ProcessingConfiguration" : ProcessingConfiguration,
            retry_options = RetryOptions,
            role_arn = kinesis_firehose_stream_role.role_arn,
            # "S3BackupMode" : String,
            s3_configuration = s3_configuration
            # "TypeName" : String
            # "VpcConfiguration" : VpcConfiguration
        )

        kinesis_firehose_stream = aws_kinesisfirehose.CfnDeliveryStream(self, "kinesis_firehose_stream",
            delivery_stream_encryption_configuration_input=None, 
            delivery_stream_name=None, 
            delivery_stream_type=None, 
            elasticsearch_destination_configuration=ElasticsearchDestinationConfiguration, 
            extended_s3_destination_configuration=None, 
            http_endpoint_destination_configuration=None, 
            kinesis_stream_source_configuration=None, 
            redshift_destination_configuration=None, 
            s3_destination_configuration=None, 
            splunk_destination_configuration=None, 
            tags=None
            )


        sqs_to_elasticsearch_service.add_environment("FIREHOSE_NAME", kinesis_firehose_stream.ref )
        sqs_to_elasticsearch_service.add_environment("QUEUEURL", sqs_to_elasticsearch_service_queue.queue_url )
        sqs_to_elasticsearch_service.add_environment("DEBUG", "False" )

        sqs_to_elastic_cloud.add_environment("ELASTICCLOUD_SECRET_NAME", "-")
        sqs_to_elastic_cloud.add_environment("ELASTIC_CLOUD_ID", "-")
        sqs_to_elastic_cloud.add_environment("ELASTIC_CLOUD_PASSWORD", "-")
        sqs_to_elastic_cloud.add_environment("ELASTIC_CLOUD_USERNAME", "-")
        sqs_to_elastic_cloud.add_environment("QUEUEURL", sqs_to_elastic_cloud_queue.queue_url )
        sqs_to_elastic_cloud.add_environment("DEBUG", "False" )
