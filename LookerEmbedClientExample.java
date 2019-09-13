import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class LookerEmbedClientExample {

    public static void main(String [] args){

        String host = "company.looker.com";  // put the port after the host if you have one, ex: "boxever.looker.com:80"
        String secret = "13175ee8bf19b798911c2473565989d01234ada50fd0c591e07e13e21edf1df6";
        String externalUserID = "\"57\"";  // converted to JSON string
        String firstName = "\"Embed Steve\""; // converted to JSON string
        String lastName = "\"Krouse\""; // converted to JSON string
        String permissions = "[\"see_user_dashboards\", \"see_lookml_dashboards\",\"access_data\",\"see_looks\"]"; // converted to JSON array
        String models = "[\"thelook\"]"; // converted to JSON array
        String groupIDs = "[5, 3]"; // converted to JSON array, can be set to null (value, not JSON) for no groups
        String externalGroupID = "\"awesome_engineers\"";  // converted to JSON string
        String sessionLength = "900";
        String embedURL = "/embed/dashboards/3";
        String forceLoginLogout = "true"; // converted to JSON bool
        String accessFilters = ("{\"thelook\": {\"dimension_a\": 1}}");  // converted to JSON Object of Objects
        String userAttributes = "{\"an_attribute_name\": \"my_attribute_value\", \"my_number_attribute\": \"42\"}";  // A Map<String, String> converted to JSON object

        try {

            String url = createURL(host, secret, externalUserID, firstName, lastName, permissions, models,
                                   sessionLength, accessFilters, embedURL, forceLoginLogout, groupIDs,
                                   externalGroupID, userAttributes);
            System.out.println("https://" + url);

        } catch(Exception e){
            System.out.println(e);
        }
    }

    public static String createURL(String host, String secret,
                                   String userID, String firstName, String lastName, String userPermissions,
                                   String userModels, String sessionLength, String accessFilters,
                                   String embedURL, String forceLoginLogout, String groupIDs,
                                   String externalGroupID, String userAttributes) throws Exception {

        String path = "/login/embed/" + java.net.URLEncoder.encode(embedURL, "UTF-8");



        Calendar cal = Calendar.getInstance();
        SecureRandom random = new SecureRandom();
        String nonce = "\"" + (new BigInteger(130, random).toString(32)) + "\"";  // converted to JSON string
        String time = Long.toString(cal.getTimeInMillis() / 1000L);

        // Order of these here is very important!
        String urlToSign = "";
        urlToSign += host + "\n";
        urlToSign += path + "\n";
        urlToSign += nonce + "\n";
        urlToSign += time + "\n";
        urlToSign += sessionLength + "\n";
        urlToSign += userID + "\n";
        urlToSign += userPermissions + "\n";
        urlToSign += userModels + "\n";
        urlToSign += groupIDs + "\n";
        urlToSign += externalGroupID + "\n";
        urlToSign += userAttributes + "\n";
        urlToSign += accessFilters;

        String signature =  encodeString(urlToSign, secret);

        // you need to %20-encode each parameter before you add to the URL
        String signedURL = "nonce="    + java.net.URLEncoder.encode(nonce, "UTF-8") +
                "&time="               + java.net.URLEncoder.encode(time, "UTF-8") +
                "&session_length="     + java.net.URLEncoder.encode(sessionLength, "UTF-8") +
                "&external_user_id="   + java.net.URLEncoder.encode(userID, "UTF-8") +
                "&permissions="        + java.net.URLEncoder.encode(userPermissions, "UTF-8") +
                "&models="             + java.net.URLEncoder.encode(userModels, "UTF-8") +
                "&access_filters="     + java.net.URLEncoder.encode(accessFilters, "UTF-8") +
                "&signature="          + java.net.URLEncoder.encode(signature, "UTF-8") +
                "&first_name="         + java.net.URLEncoder.encode(firstName, "UTF-8") +
                "&last_name="          + java.net.URLEncoder.encode(lastName, "UTF-8") +
                "&group_ids="          + java.net.URLEncoder.encode(groupIDs, "UTF-8") +
                "&external_group_id="  + java.net.URLEncoder.encode(externalGroupID, "UTF-8") +
                "&user_attributes="    + java.net.URLEncoder.encode(userAttributes, "UTF-8") +
                "&force_logout_login=" + java.net.URLEncoder.encode(forceLoginLogout, "UTF-8");

        return host + path + '?' + signedURL;

    }

    public static String encodeString(String stringToEncode, String secret) throws Exception {
        byte[] keyBytes = secret.getBytes();
        SecretKeySpec signingKey = new SecretKeySpec(keyBytes, "HmacSHA1");
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(signingKey);
        byte[] rawHmac = Base64.getEncoder().encode(mac.doFinal(stringToEncode.getBytes("UTF-8")));
        return new String(rawHmac, "UTF-8");
    }
}
