
        ###########################################################################
        # AWS ALB for Elasticsearch and PrivateLink
        # https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_apigatewayv2.README.html
        ###########################################################################
        elasticsearch_alb=aws_elasticloadbalancingv2.


        ###########################################################################
        # AWS API GATEWAY
        # https://docs.aws.amazon.com/cdk/api/latest/python/aws_cdk.aws_apigatewayv2.README.html
        ###########################################################################
        elasticsearch_proxy_integration = aws_apigatewayv2.HttpProxyIntegration(
            url="https://get-books-proxy.myproxy.internal"
        )
        http_api = aws_apigatewayv2.HttpApi(self, "elasticsearchttpApi")
        http_api.add_routes(
            path="/elasticsearch",
            methods=[aws_apigatewayv2.HttpMethod.ANY],
            integration=elasticsearch_proxy_integration
        )