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
        String groupIds = "[5, 3]"; // converted to JSON array, can be set to null (value, not JSON) for no groups
        String sessionLength = "900";
        String embedURL = "/embed/sso/dashboards/3";
        String forceLoginLogout = "true"; // converted to JSON bool
        String accessFilters = ("{\"thelook\": {\"dimension_a\": 1}}");  // converted to JSON Object of Objects

        try {

            String url = createURL(host, secret, externalUserID, firstName, lastName, permissions, models,
                                   sessionLength, groupIds, accessFilters, embedURL, forceLoginLogout);
            System.out.println("https://" + url);

        } catch(Exception e){
            System.out.println(e);
        }
    }

    public static String createURL(String host, String secret,
                                   String userID, String firstName, String lastName, String userPermissions,
                                   String userModels, String sessionLength, String groupIds, String accessFilters,
                                   String embedURL, String forceLoginLogout) throws Exception {

        String path = "/login/embed/" + java.net.URLEncoder.encode(embedURL, "ISO-8859-1");



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
        urlToSign += groupIds + "\n";
        urlToSign += accessFilters;

        String signature =  encodeString(urlToSign, secret);

        // you need to %20-encode each parameter before you add to the URL
        String signedURL = "nonce="    + java.net.URLEncoder.encode(nonce, "ISO-8859-1") +
                "&time="               + java.net.URLEncoder.encode(time, "ISO-8859-1") +
                "&session_length="     + java.net.URLEncoder.encode(sessionLength, "ISO-8859-1") +
                "&external_user_id="   + java.net.URLEncoder.encode(userID, "ISO-8859-1") +
                "&permissions="        + java.net.URLEncoder.encode(userPermissions, "ISO-8859-1") +
                "&models="             + java.net.URLEncoder.encode(userModels, "ISO-8859-1") +
                "&access_filters="     + java.net.URLEncoder.encode(accessFilters, "ISO-8859-1") +
                "&signature="          + java.net.URLEncoder.encode(signature, "ISO-8859-1") +
                "&first_name="         + java.net.URLEncoder.encode(firstName, "ISO-8859-1") +
                "&last_name="          + java.net.URLEncoder.encode(lastName, "ISO-8859-1") +
                "&group_ids="          + java.net.URLEncoder.encode(groupIds, "ISO-8859-1") +
                "&force_logout_login=" + java.net.URLEncoder.encode(forceLoginLogout, "ISO-8859-1");

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
