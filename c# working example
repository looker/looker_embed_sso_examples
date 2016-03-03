using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Web;


namespace GetUrl
{
	internal class Program
	{

		private static void Main(string[] args)
		{

			String accessFilters = "{}"; // converted to JSON Object of Objects
			// String accessFilters = ("{\"model_name\":{\"view_name.field_name\": \"'Your Value'\"}}");
			         
			String embedURL = "/embed/looks/10";

			String externalUserID = "\"1\""; // converted to JSON string
			String firstName = "\"Embed\""; // converted to JSON string
			String lastName = "\"Person\""; // converted to JSON string
			String forceLoginLogout = "true"; // converted to JSON bool

			String host = "looker.hostname.com:9999";
			// put the port after the host if you have one, ex: "boxever.looker.com:80, else exclude it"


			String models = "[\"my_model\"]"; // converted to JSON array

			String permissions =
				"[\"see_user_dashboards\", \"see_lookml_dashboards\",\"access_data\",\"see_looks\"]";
			// converted to JSON array

			String secret = "your_secret";
			String sessionLength = "900";
			
			var builder = new UriBuilder
			{
				Host = host,
				Path = "/login/embed/" + System.Net.WebUtility.UrlEncode(embedURL)

			};

			var nonce = $"\"{DateTime.Now.Ticks}\"";

			String path = "/login/embed/" + System.Net.WebUtility.UrlEncode(embedURL);
			String urlToSign = "";
			urlToSign += host + "\n";
			urlToSign += builder.Path + "\n";
			urlToSign += nonce + "\n";
			//urlToSign += time + "\n";
			urlToSign += sessionLength + "\n";
			urlToSign += externalUserID + "\n";
			urlToSign += permissions + "\n";
			urlToSign += models + "\n";
			urlToSign += accessFilters;
			Console.WriteLine(urlToSign);
			String signature = EncodeString(urlToSign, secret);
			Console.WriteLine (signature);
			Int32 unixTime = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

			string time = string.Format("{0}", unixTime);
			String signedURL = "nonce=" + System.Net.WebUtility.UrlEncode(nonce) +
				"&time=" + System.Net.WebUtility.UrlEncode(time) +
				"&session_length=" + System.Net.WebUtility.UrlEncode(sessionLength) +
				"&external_user_id=" + System.Net.WebUtility.UrlEncode(externalUserID) +
				"&permissions=" + System.Net.WebUtility.UrlEncode(permissions) +
				"&models=" + System.Net.WebUtility.UrlEncode(models) +
				"&access_filters=" + System.Net.WebUtility.UrlEncode(accessFilters) +
				"&signature=" + System.Net.WebUtility.UrlEncode(signature) +
				"&first_name=" + System.Net.WebUtility.UrlEncode(firstName) +
				"&last_name=" + System.Net.WebUtility.UrlEncode(lastName) +
				"&force_logout_login=" + System.Net.WebUtility.UrlEncode(forceLoginLogout);


			Console.WriteLine("https://" + host + path + '?' + signedURL);

		}

		private static string EncodeString(string urlToSign, string secret)
		{


			var bytes = Encoding.UTF8.GetBytes(secret);
			var stringToEncode = Encoding.UTF8.GetBytes(urlToSign);
			using (HMACSHA1 hmac = new HMACSHA1(bytes))
			{
				var rawHmac = hmac.ComputeHash(stringToEncode);
				return  Convert.ToBase64String(rawHmac);
			}

		}

	}
}
