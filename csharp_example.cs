using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SSOTest
{
	class Program
	{
		static void Main(string[] args)
		{
			var user_attributes = new Dictionary<string, string>();
			user_attributes["an_attribute_name"] = "my_attribute_value";
			user_attributes["my_number_attribute"] = "1000.232";
			var config = new LookerEmbedConfiguration()
			{
				HostName = "your-hostname.looker.com",
				//HostPort = 9999,
				Secret = "--- your secret here ---",
				ExternalUserId = "57",
				UserFirstName = "Embed",
				UserLastName = "User",
				Permissions = new string[] {"explore", "see_user_dashboards", "see_lookml_dashboards","access_data","see_looks", "download_with_limit"},
				Models = new string[] { "imdb" },
				GroupIds = new int[] {4, 2},
				ExternalGroupId = "awesome_engineers",
				UserAttributeMapping = user_attributes
			};

			string url = GetLookerEmbedUrl("/embed/dashboards/1", config);

			Console.WriteLine(url);
			Console.ReadLine();
		}

		public class LookerEmbedConfiguration
		{
			// AccessFilters holds a JSON serialized object tree describing the access control filters
			// {"model_name":{"view_name.field_name": "'Your Value'"}}"
			public string AccessFilters { get; set; }
			public string ExternalUserId { get; set; }
			public string UserFirstName { get; set; }
			public string UserLastName { get; set; }
			public bool ForceLogoutLogin { get; set; }
			public string[] Models { get; set; }
			public int[] GroupIds { get; set; }
			public string ExternalGroupId { get; set; }
			public string[] Permissions { get; set; }
			public Dictionary<string, string> UserAttributeMapping { get; set; }
			public string Secret { get; set; }
			public TimeSpan SessionLength { get; set; }
			public string HostName { get; set; }
			public int HostPort { get; set; }
			public string Nonce { get; set; }

			public LookerEmbedConfiguration()
			{
				ForceLogoutLogin = true;
				SessionLength = TimeSpan.FromMinutes(15);
				Nonce = DateTime.Now.Ticks.ToString();
				AccessFilters = "{}";
			}
		}

		public static Uri GetLookerEmbedUrl(string targetPath, LookerEmbedConfiguration config)
		{
		  var uri = new UriBuilder
		  {
		    Scheme = "https",
		    Host = config.HostName,
		    Port = config.HostPort,
		    Path = "/login/embed/"
		  };

		  var builder = new StringBuilder();
		  builder.AppendFormat("{0}://{1}{2}{3}", uri.Scheme, uri.Uri.Authority, uri.Path,
		    UrlEncodeForLooker(targetPath));

			var unixTime = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
			var time = unixTime.ToString();
			var json_nonce = JsonConvert.SerializeObject(config.Nonce);
			var json_external_user_id = JsonConvert.SerializeObject(config.ExternalUserId);
			var json_permissions = JsonConvert.SerializeObject(config.Permissions);
			var json_group_ids = JsonConvert.SerializeObject(config.GroupIds);
			var json_external_group_id = JsonConvert.SerializeObject(config.ExternalGroupId);
			var json_user_attribute_values = JsonConvert.SerializeObject(config.UserAttributeMapping);
			var json_models = JsonConvert.SerializeObject(config.Models);
			var json_session_length = ((long)config.SessionLength.TotalSeconds).ToString();

			// order of elements is important
			var stringToSign = String.Join("\n", new string[] {
			  uri.Uri.Authority,
			  "/login/embed/" + UrlEncodeForLooker(targetPath),
				json_nonce,
				time,
				json_session_length,
				json_external_user_id,
				json_permissions,
				json_models,
				json_group_ids,
				json_external_group_id,
				json_user_attribute_values,
				config.AccessFilters
			});

			var signature = EncodeString(stringToSign, config.Secret);

			var json_first_name = JsonConvert.SerializeObject(config.UserFirstName);
			var json_last_name = JsonConvert.SerializeObject(config.UserLastName);
			var json_force_logout_login = JsonConvert.SerializeObject(config.ForceLogoutLogin);

			var qparams = new Dictionary<string, string>()
			{
				{ "nonce", json_nonce },
				{ "time", time },
				{ "session_length", json_session_length },
				{ "external_user_id", json_external_user_id },
				{ "permissions", json_permissions },
				{ "models", json_models },
				{ "group_ids", json_group_ids },
				{ "external_group_id", json_external_group_id },
				{ "user_attributes", json_user_attribute_values },
				{ "access_filters", config.AccessFilters},
				{ "first_name", json_first_name },
				{ "last_name", json_last_name },
				{ "force_logout_login", json_force_logout_login },
				{ "signature", signature }
			};

		  builder.Append("?");
		  builder.Append(string.Join("&", qparams.Select(kvp => kvp.Key + "=" + (UrlEncodeForLooker(kvp.Value)))));

		  return builder.ToString();
		}

	  /// <summary>
	  /// Looker's URL encoding REQUIRES hex numbers to be uppercase: %2F, not %2f.
	  /// So, we use a custom url encoder; dotnet's built-in one emits lower case hex.
	  /// Looker gacks on that.
	  /// <remarks>WTF?</remarks>
	  /// </summary>
	  /// <param name="i">string to UrlEncodeForLooker</param>
	  /// <returns>encoded string</returns>
	  private static string UrlEncodeForLooker(string i)
	  {
	    var b = new StringBuilder();
	    foreach (var c in i)
	    {
	      if (char.IsLetterOrDigit(c)) b.Append(c);
	      else b.Append('%').Append(((int)c).ToString("X"));
	    }

	    return b.ToString();
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
