from aws_cdk import core
from cdk.cdk_stack import CdkStack
from aws_cdk.core import App, Stack, Tags


app = core.App()
# app.build()
s3_to_elasticsearch_access_logs_stack = CdkStack(app, "s3-to-elasticsearch-access-logs")
# mystack = CdkStack(app, "cdk")

# Tag.add(s3_to_elasticsearch_access_logs_stack, "auto-delete", "no")
Tags.of(s3_to_elasticsearch_access_logs_stack).add("auto-delete","no")

app.synth()
#!/usr/bin/env python3
