using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Elasticsearch.Net.Connection.Configuration;
using Elasticsearch.Net.Connection;
using Elasticsearch.Net;
using System.Security.Cryptography;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace Nesthub.AWS
{
    public class HttpClientConnectionAWS: IConnection, IDisposable
    {
        #region Amazon Signing Members
        /// <summary>
        /// 
        /// </summary>
        private string AccessKey;
       
        /// <summary>
        /// 
        /// </summary>
        private string SecretKey;

        /// <summary>
        /// 
        /// </summary>
        private string Region;
        
        /// <summary>
        /// 
        /// </summary>
        private string ServiceName
        {
            get
            {
                return "es";
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        static byte[] HmacSHA256(string data, byte[] key)
        {
            String algorithm = "HmacSHA256";
            KeyedHashAlgorithm kha = KeyedHashAlgorithm.Create(algorithm);
            kha.Key = key;

            return kha.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Get the signature key used to sign the AWS request
        /// </summary>
        /// <param name="key"></param>
        /// <param name="dateStamp"></param>
        /// <param name="regionName"></param>
        /// <param name="serviceName"></param>
        /// <returns></returns>
        static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName)
        {
            byte[] kSecret = Encoding.UTF8.GetBytes(("AWS4" + key).ToCharArray());
            byte[] kDate = HmacSHA256(dateStamp, kSecret);
            byte[] kRegion = HmacSHA256(regionName, kDate);
            byte[] kService = HmacSHA256(serviceName, kRegion);
            byte[] kSigning = HmacSHA256("aws4_request", kService);
 
            return kSigning;
        }

        /// <summary>
        /// Build the canonical string for the request and compute the signature, then add the necesary headers to the request object
        /// </summary>
        /// <param name="request"></param>
        /// <param name="method"></param>
        /// <param name="uri"></param>
        /// <param name="data"></param>
        private void AddAWSSignature(HttpRequestMessage request, HttpMethod method, Uri uri, byte[] data)
        {
            // Getting timestamps
            string amz_date = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ");
            string date_stamp = DateTime.UtcNow.ToString("yyyyMMdd");

            //# ************* TASK 1: CREATE A CANONICAL REQUEST *************
            //# http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

            //# Step 1 is to define the verb (GET, POST, etc.)--
            string verb = method.Method.ToUpper();


            //# Step 2: Create canonical URI--the part of the URI from domain to query 
            //# string (use '/' if no path)
            string canonical_uri = uri.PathAndQuery.Split('?')[0];
            if (String.IsNullOrEmpty(canonical_uri)) canonical_uri = "/";

            // Step 3: Create the canonical query string if any.
            string canonical_querystring = (uri.PathAndQuery.Split('?').Length > 1) ? uri.PathAndQuery.Split('?')[1] : "";

            // Step 4: Create the canonical headers. Header names and values
            // must be trimmed and lowercase, and sorted in ASCII order.
            string canonical_headers = "content-type:" + DefaultContentType + "\n" + "host:" + uri.Host + "\n" + "x-amz-date:" + amz_date;

            // Step 5: Create the list of signed headers. This lists the headers
            // in the canonical_headers list, delimited with ";" and in alpha order.
            // Note: The request can include any headers; canonical_headers and
            // signed_headers include those that you want to be included in the
            // hash of the request. "Host" and "x-amz-date" are always required.
            // For DynamoDB, content-type and x-amz-target are also required.
            string signed_headers = "content-type;host;x-amz-date";

            // Step 6: Create payload hash. The payload (body of
            // the request) contains the request parameters.
            // create a hashing object                    
            SHA256Managed hashingObj = new SHA256Managed();
            byte[] ba1 = hashingObj.ComputeHash(data);
            string payload = string.Empty;
            if (data != null && data.Length > 0)
            {
                payload = System.Text.Encoding.UTF8.GetString(data);
            }
            string payload_hash = BitConverter.ToString(ba1).Replace("-", string.Empty).ToLower();


            //# Step 7: Combine elements to create create canonical request
            string canonicalString = string.Empty;
            if (string.IsNullOrEmpty(canonical_querystring))
                canonicalString = verb + "\n" + canonical_uri + "\n\n" + canonical_headers + "\n\n" + signed_headers + "\n" + payload_hash;
            else
                canonicalString = verb + "\n" + canonical_uri + "\n\n" + canonical_headers + "\n\n" + canonical_querystring + "\n\n" + signed_headers + "\n" + payload_hash;

            //# ************* TASK 2: CREATE THE STRING TO SIGN*************
            //# Match the algorithm to the hashing algorithm you use, either SHA-1 or
            //# SHA-256 (recommended)
            string algorithm = "AWS4-HMAC-SHA256";
            string credential_scope = date_stamp + "/" + Region + "/" + ServiceName + "/" + "aws4_request";
            byte[] ba2 = hashingObj.ComputeHash(System.Text.Encoding.UTF8.GetBytes(canonicalString));
            string canonicalHash = BitConverter.ToString(ba2).Replace("-", string.Empty).ToLower();
            string string_to_sign = algorithm + '\n' + amz_date + '\n' + credential_scope + '\n' + canonicalHash;


            //# ************* TASK 3: CALCULATE THE SIGNATURE *************
            //# Create the signing key using the function defined above.
            HMACSHA256 signature = new HMACSHA256(getSignatureKey(SecretKey, date_stamp, Region, ServiceName));

            //# Sign the string_to_sign using the signing_key
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(string_to_sign);
            byte[] ba3 = signature.ComputeHash(bytes);
            string signatureValue = BitConverter.ToString(ba3).Replace("-", string.Empty).ToLower();
            // create a hashing object     


            //# ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
            //# Put the signature information in a header named Authorization.

            string authorization_header = algorithm + " " + "Credential=" + AccessKey + "/" + credential_scope + ", " + "SignedHeaders=" + signed_headers + ", " + "Signature=" + signatureValue;
            request.Headers.TryAddWithoutValidation("x-amz-date", amz_date);
            request.Headers.TryAddWithoutValidation("Authorization", authorization_header);
        }

        #endregion

        private readonly IConnectionConfigurationValues _settings;

		static HttpClientConnectionAWS()
		{
			// brought over from HttpClient
			ServicePointManager.UseNagleAlgorithm = false;
			ServicePointManager.Expect100Continue = false;

			// this should be set globally based on _settings.MaximumAsyncConnections
			ServicePointManager.DefaultConnectionLimit = 10000;

            // Init 
            
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="HttpClientConnection"/> class.
		/// </summary>
		/// <param name="settings">The settings.</param>
		/// <param name="handler">The handler.</param>
		public HttpClientConnectionAWS(IConnectionConfigurationValues settings, string accessKey, string secretKey, string region, HttpClientHandler handler = null)
		{
			_settings = settings;
			DefaultContentType = "application/json";

			var innerHandler = handler ?? new WebRequestHandler();

			if (innerHandler.SupportsProxy && !string.IsNullOrWhiteSpace(_settings.ProxyAddress))
			{
				innerHandler.Proxy = new WebProxy(_settings.ProxyAddress)
				{
					Credentials = new NetworkCredential(_settings.ProxyUsername, _settings.ProxyPassword),
				};

				innerHandler.UseProxy = true;
			}

			Client = new HttpClient(new InternalHttpMessageHandler(innerHandler), false)
			{
				Timeout = TimeSpan.FromMilliseconds(_settings.Timeout)
			};

            this.AccessKey = accessKey;
            this.SecretKey = secretKey;
            this.Region = region;
		}

		/// <summary>
		/// Gets or sets the default type of the content.
		/// </summary>
		/// <value>The default type of the content.</value>
		public string DefaultContentType { get; set; }

		/// <summary>
		/// Gets a value indicating whether this instance is disposed.
		/// </summary>
		/// <value><c>true</c> if this instance is disposed; otherwise, <c>false</c>.</value>
		public bool IsDisposed { get; private set; }

		/// <summary>
		/// Gets the client.
		/// </summary>
		/// <value>The client.</value>
		public HttpClient Client { get; private set; }

		/// <summary>
		/// Wraps the DoRequest to run synchronously
		/// </summary>
		/// <param name="method">The method.</param>
		/// <param name="uri">The URI.</param>
		/// <param name="data">The data.</param>
		/// <param name="requestSpecificConfig">The request specific configuration.</param>
		/// <returns>ElasticsearchResponse&lt;Stream&gt;.</returns>
		public ElasticsearchResponse<Stream> DoRequestSync(HttpMethod method, Uri uri, byte[] data = null, IRequestConfiguration requestSpecificConfig = null)
		{
			ThrowIfDisposed();

			var requestTask = DoRequest(method, uri, data, requestSpecificConfig);

			try
			{
				requestTask.Wait();
				return requestTask.Result;
			}
			catch (AggregateException ex)
			{
				return ElasticsearchResponse<Stream>.CreateError(_settings, ex.Flatten(), method.ToString().ToLowerInvariant(), uri.ToString(), data);
			}
			catch (Exception ex)
			{
				return ElasticsearchResponse<Stream>.CreateError(_settings, ex, method.ToString().ToLowerInvariant(), uri.ToString(), data);
			}
		}

		/// <summary>
		/// Makes an async call to the specified url. Uses the timeout from the IRequestSpecifiConfig is supplied, or the global timeout from settings.
		/// </summary>
		/// <param name="method">The method.</param>
		/// <param name="uri">The URI.</param>
		/// <param name="data">The data.</param>
		/// <param name="requestSpecificConfig">The request specific configuration.</param>
		/// <returns>Task&lt;ElasticsearchResponse&lt;Stream&gt;&gt;.</returns>
		public async Task<ElasticsearchResponse<Stream>> DoRequest(HttpMethod method, Uri uri, byte[] data = null, IRequestConfiguration requestSpecificConfig = null)
		{
			ThrowIfDisposed();

			try
			{
				var request = new HttpRequestMessage(method, uri);

                AddAWSSignature(request, method, uri, data);                

				if (method != HttpMethod.Get && method != HttpMethod.Head && data != null && data.Length > 0)
				{
					request.Content = new ByteArrayContent(data);

					if (requestSpecificConfig != null && !string.IsNullOrWhiteSpace(requestSpecificConfig.ContentType))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(requestSpecificConfig.ContentType));
					}
					else if (!string.IsNullOrWhiteSpace(DefaultContentType))
					{
						request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue(DefaultContentType));
					}

					if (!string.IsNullOrWhiteSpace(DefaultContentType))
					{
						request.Content.Headers.ContentType = new MediaTypeHeaderValue(DefaultContentType);
					}
				}

				var response = await Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);

				if (method == HttpMethod.Head || response.Content == null || !response.Content.Headers.ContentLength.HasValue || response.Content.Headers.ContentLength.Value <= 0)
				{
					return ElasticsearchResponse<Stream>.Create(_settings, (int)response.StatusCode, method.ToString().ToLowerInvariant(), uri.ToString(), data);
				}

				var responseStream = await response.Content.ReadAsStreamAsync();
				return ElasticsearchResponse<Stream>.Create(_settings, (int)response.StatusCode, method.ToString().ToLowerInvariant(), uri.ToString(), data, responseStream);

			}
			catch (Exception ex)
			{
				return ElasticsearchResponse<Stream>.CreateError(_settings, ex, method.ToString().ToLowerInvariant(), uri.ToString(), data);
			}
		}

        

		Task<ElasticsearchResponse<Stream>> IConnection.Get(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Get, uri, null, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.GetSync(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Get, uri, null, requestSpecificConfig);
		}

		Task<ElasticsearchResponse<Stream>> IConnection.Head(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Head, uri, null, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.HeadSync(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Head, uri, null, requestSpecificConfig);
		}

		Task<ElasticsearchResponse<Stream>> IConnection.Post(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Post, uri, data, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.PostSync(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Post, uri, data, requestSpecificConfig);
		}

		Task<ElasticsearchResponse<Stream>> IConnection.Put(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Put, uri, data, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.PutSync(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Put, uri, data, requestSpecificConfig);
		}

		Task<ElasticsearchResponse<Stream>> IConnection.Delete(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Delete, uri, null, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.DeleteSync(Uri uri, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Delete, uri, null, requestSpecificConfig);
		}

		Task<ElasticsearchResponse<Stream>> IConnection.Delete(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequest(HttpMethod.Delete, uri, data, requestSpecificConfig);
		}

		ElasticsearchResponse<Stream> IConnection.DeleteSync(Uri uri, byte[] data, IRequestConfiguration requestSpecificConfig)
		{
			return DoRequestSync(HttpMethod.Delete, uri, data, requestSpecificConfig);
		}

		private void ThrowIfDisposed()
		{
			if (IsDisposed)
			{
				throw new ObjectDisposedException(GetType().Name);
			}
		}

		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

        ~HttpClientConnectionAWS()
		{
			Dispose(false);
		}

		protected virtual void Dispose(bool disposing)
		{
			if (IsDisposed)
				return;

			if (disposing)
			{
				if (Client != null)
				{
					Client.Dispose();
					Client = null;
				}
			}

			IsDisposed = true;
		}

        public TransportAddressScheme? AddressScheme { get; private set; }
    }
}
