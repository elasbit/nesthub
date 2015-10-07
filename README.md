# nesthub
Http connectors for Elasticsearch.Net Client


HttpClientConnectionAWS

If you are migrating you Elasticsearch cluster to the new Amazon Elasticsearch Service, you will notice that if you secure your cluster, then you wil need to sing all the http rest request.

Unless you use the AWS SDK, the signing process can be tricky. This conector encapsulate the proccess of signing the request for Amazon Elasticsearch Service.


Usage:

When using Nest, simply pass an instance of "HttpClientConnectionAWS" when creating an elasticsearh client.

You will need to provide your Account Acces Key and Secret Key since they are required to sign the request.

var elasticSettings = new ConnectionSettings(new System.Uri("EsUrl"));

// Set the connection Implementation to httpclient Implementation

IConnection elasticConnection = new HttpClientConnectionAWS( elasticSettings, "AccessKey", "SecretKey", "Region" );

var client = new ElasticClient(elasticSettings, elasticConnection);
