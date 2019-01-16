using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace YahooWeather
{
    class Program
    {
        static void Main(string[] args)
        {
            //Converting the java example to the page https://developer.yahoo.com/weather/documentation.html

            string appId = "test-app-id";
            string consumerKey = "your-consumer-key";
            string consumerSecret = "your-consumer-secret";
            string url = "https://weather-ydn-yql.media.yahoo.com/forecastrss";
            string timestamp = Math.Truncate((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds).ToString();
            string oauthNonce = Guid.NewGuid().ToString().Replace("-", "");
            List<string> parameters = new List<string>();

            parameters.Add("oauth_consumer_key=" + EscapeUriDataStringRfc3986(consumerKey));
            parameters.Add("oauth_nonce=" + EscapeUriDataStringRfc3986(oauthNonce));
            parameters.Add("oauth_signature_method=HMAC-SHA1");
            parameters.Add("oauth_timestamp=" + EscapeUriDataStringRfc3986(timestamp));
            parameters.Add("oauth_version=1.0");
            // Make sure value is encoded
            parameters.Add("location=" + EscapeUriDataStringRfc3986("sunnyvale,ca"));
            parameters.Add("format=json");
            parameters.Add("u=f");

            parameters.Sort();

            StringBuilder parametersList = new StringBuilder();
            for (int i = 0; i < parameters.Count; i++)
                parametersList.Append(((i > 0) ? "&" : "") + parameters[i]);

            string signatureString = "GET&" + EscapeUriDataStringRfc3986(url) + "&" +
                                      EscapeUriDataStringRfc3986(parametersList.ToString());

            byte[] secretKey = Encoding.UTF8.GetBytes(consumerSecret + "&");
            HMACSHA1 hmac = new HMACSHA1(secretKey);
            hmac.Initialize();
            byte[] bytes = Encoding.UTF8.GetBytes(signatureString);
            byte[] rawHmac = hmac.ComputeHash(bytes);
            string signature = Convert.ToBase64String(rawHmac);

            string authorizationLine = "oauth_consumer_key=\"" + consumerKey + "\", " +
            "oauth_nonce=\"" + oauthNonce + "\", " +
            "oauth_timestamp=\"" + timestamp + "\", " +
            "oauth_signature_method=\"HMAC-SHA1\", " +
            "oauth_signature=\"" + signature + "\", " +
            "oauth_version=\"1.0\"";

            HttpClientHandler handler = new HttpClientHandler() { UseDefaultCredentials = false };
            using (HttpClient client = new HttpClient(handler))
            {
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Add("Yahoo-App-Id", appId);
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", authorizationLine);

                HttpResponseMessage response = client.GetAsync($"{url}?location=sunnyvale,ca&format=json&u=f").Result;

                string responseString = response.Content.ReadAsStringAsync().Result;

                if (!string.IsNullOrEmpty(responseString) && response.StatusCode == System.Net.HttpStatusCode.OK && responseString.ToLower().IndexOf("error") < 0)
                {
                    Console.WriteLine(responseString);
                }
                else
                {
                    //Error
                }
            }
        }

        // <summary>
        /// Escapes a string according to the URI data string rules given in RFC 3986.
        /// </summary>
        /// <param name="value">The value to escape.</param>
        /// <returns>The escaped value.</returns>
        /// <remarks>
        /// The <see cref="Uri.EscapeDataString"/> method is <i>supposed</i> to take on
        /// RFC 3986 behavior if certain elements are present in a .config file.  Even if this
        /// actually worked (which in my experiments it <i>doesn't</i>), we can't rely on every
        /// host actually having this configuration element present.
        /// </remarks>
        private static string EscapeUriDataStringRfc3986(string value)
        {
            // The set of characters that are unreserved in RFC 2396 but are NOT unreserved in RFC 3986.
            string[] UriRfc3986CharsToEscape = new[] { "!", "*", "'", "(", ")" };

            // Start with RFC 2396 escaping by calling the .NET method to do the work.
            // This MAY sometimes exhibit RFC 3986 behavior (according to the documentation).
            // If it does, the escaping we do that follows it will be a no-op since the
            // characters we search for to replace can't possibly exist in the string.
            StringBuilder escaped = new StringBuilder(Uri.EscapeDataString(value));

            // Upgrade the escaping to RFC 3986, if necessary.
            for (int i = 0; i < UriRfc3986CharsToEscape.Length; i++)
                escaped.Replace(UriRfc3986CharsToEscape[i], Uri.HexEscape(UriRfc3986CharsToEscape[i][0]));

            // Return the fully-RFC3986-escaped string.
            return escaped.ToString();
        }
    }
}
