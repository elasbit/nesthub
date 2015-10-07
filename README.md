# nesthub
Http connectors for Nest Client



When using Nest, simply pass an instance of "HttpClientConnectionAWS" when creating an elasticsearh client.

You will need to provide your Account Acces Key and Secret Key since they are required to sign the request.

var elasticSettings = new ConnectionSettings(new System.Uri("EsUrl"));

// Set the connection Implementation to httpclient Implementation

IConnection elasticConnection = new HttpClientConnectionAWS( elasticSettings, "AccessKey", "SecretKey", "Region" );

var client new ElasticClient(elasticSettings, elasticConnection);
