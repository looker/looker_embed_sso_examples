using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Security.Cryptography;

namespace LookerEmbeddedUrl
{
    class Program
    {

        public static string _access_token = "";

        public static string _EmbedSecret = "13175ee8bf19b798911c2473565989d01234ada50fd0c591e07e13e21edf1df6"; // Hosted Looker Instance

        public static string _host = "https://company.looker.com";

        static void Main(string[] args)
        {
            string externalUserID = "\"user@mygreatproduct.com\"";      // converted to JSON string
            string firstName = "\"Embed Jon\"";                         // converted to JSON string
            string lastName = "\"Smith\"";                              // converted to JSON string
            string permissions = "[\"see_user_dashboards\", \"see_lookml_dashboards\",\"access_data\",\"see_looks\"]"; // converted to JSON array
            string models = "[\"thelook\"]";                            // converted to JSON array
            string sessionLength = "900";                               // session length
            string embedURL = "/embed/dashboards/thelook/buyer_analytics";                  // LookML dashboard use "/embed/sso/dashboards/3" for user defined dashboards
            string forceLoginLogout = "true";                           // converted to JSON bool
            string accessFilters = ("{\"thelook\": {\"dadataaccessfact.id\": \"1222\"}}");  // { <model name> : { <TableName.ColumnName>: <value>} 

            // Use the class to generate the embed URL
            string signedURL = LookerEmbedClient.CreateURL(_host, _EmbedSecret, externalUserID,
                firstName, lastName, permissions, models, sessionLength, accessFilters, embedURL, forceLoginLogout);

            System.Console.WriteLine(signedURL);
            System.Console.WriteLine("\r\nPress any key to quit");
            System.Console.ReadKey();
        }
    }

    public class LookerEmbedClient
    {
        public static String CreateURL(String host, String secret,
                                       String userID, String firstName, String lastName, String userPermissions,
                                       String userModels, String sessionLength, String accessFilters,
                                       String embedURL, String forceLoginLogout)
        {
            String path = "/login/embed/" + WebUtility.UrlEncode(embedURL);

            // Calc the secure random number (nonce)
            Guid g = Guid.NewGuid();
            string nonce = string.Format("\"{0}\"", g.ToString().Replace("-", ""));

            // calc the unix timestamp value 
            Int32 unixTime = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

            string time = string.Format("{0}", unixTime);

            string urlToSign = "";
            urlToSign += host.Replace("https://", "") + "\n";
            urlToSign += path + "\n";
            urlToSign += nonce + "\n";
            urlToSign += time + "\n";
            urlToSign += sessionLength + "\n";
            urlToSign += userID + "\n";
            urlToSign += userPermissions + "\n";
            urlToSign += userModels + "\n";
            urlToSign += accessFilters + "\n";

            // Generate the signature using the urlToSign
            string signature = GetHash(urlToSign, secret);


            // you need to %20-encode each parameter before you add to the URL
            String signedURL = "nonce=" + WebUtility.UrlEncode(nonce) +
                    "&time=" + WebUtility.UrlEncode(time) +
                    "&session_length=" + WebUtility.UrlEncode(sessionLength) +
                    "&external_user_id=" + WebUtility.UrlEncode(userID) +
                    "&permissions=" + WebUtility.UrlEncode(userPermissions) +
                    "&models=" + WebUtility.UrlEncode(userModels) +
                    "&access_filters=" + WebUtility.UrlEncode(accessFilters) +
                    "&signature=" + WebUtility.UrlEncode(signature) +
                    "&first_name=" + WebUtility.UrlEncode(firstName) +
                    "&last_name=" + WebUtility.UrlEncode(lastName) +
                    "&force_logout_login=" + WebUtility.UrlEncode(forceLoginLogout);

            return host + path + '?' + signedURL;
        }

        static string GetHash(string hashText, string SecretKey)
        {
            using (HMACSHA1 hmac = new HMACSHA1(Encoding.UTF8.GetBytes(SecretKey)))
            {
                byte[] raw1 = Encoding.UTF8.GetBytes(hashText);
                byte[] hashValue = hmac.ComputeHash(raw1);
                return Convert.ToBase64String(hashValue);
            }
        }
    }

}


