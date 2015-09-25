/*
The steps to make this work:

1) Create the class below and included associated test cases.
2) Create a Visual Force Component using this code:

<apex:component controller="UCEmbedLookerController">
    <apex:attribute name="embedHeight" description="This is height to embed" type="String" required="false" />
    <apex:attribute name="embedWidth" description="This is width to embed" type="String" required="false"/>
    <apex:attribute name="embedPath" description="This is url to embed" type="String" required="true" assignTo="{!embed_path}"/>
    <apex:attribute name="lookerModels" description="This is url to embed" type="String" required="true" assignTo="{!looker_models}"/>
    <apex:attribute name="lookerPermissions" description="This is url to embed" type="String" required="true" assignTo="{!looker_permissions}"/>    
    <apex:attribute name="lookerAccessFilters" description="This is url to embed" type="String" required="true" assignTo="{!looker_access_filters}"/>    
    <iframe src="{!generateIframeUrl}" width="{!embedWidth}" height="{!embedHeight}" frameborder="0"></iframe>
</apex:component>

3) Reference the component in a visual force page or somewhere using (note when using JSON use ', not ", it gets converted in the backend to ":

<apex:page >
    <c:UCEmbedLooker embedPath="/embed/dashboards/1" lookerModels="orders" 
                    lookerPermissions="access_data,see_looks,see_lookml_dashboards,see_user_dashboards,explore"  
                    lookerAccessFilters="{'orders':{}}" />
</apex:page>
*/



public class UCEmbedLookerController {

    private string looker_host = 'company.looker.com';
    private string looker_secret = '13175ee8bf19b798911c2473565989d01234ada50fd0c591e07e13e21edf1df6';
    public string embed_path {get; set;}
    public string looker_models {get; set;}
    public string looker_permissions {get; set;}
    public string looker_access_filters {get; set;}
        
    public class UCLookerInstance{
        string host {get;set;}
        string secret {get;set;}
        
        public UCLookerInstance(string host, string secret){
            this.host = host;
            this.secret = secret;
        }
    }
    
    public class UCLookerUser {
        string external_user_id {get;set;}
        string first_name {get;set;}
        string last_name {get;set;}
        string models {get;set;}
        string permissions {get;set;}
        string access_filters {get;set;}
        
        public string getCurrentUserEmail(){
          return [SELECT Id, Email FROM User WHERE Id = :UserInfo.getUserId() LIMIT 1].Email;
      }
        
        public UCLookerUser(string email, string first_name, string last_name, string[] models, string[] permissions, Object access_filters){
          if (email == null){
          this.external_user_id = json.serialize(this.getCurrentUserEmail());
          } else {
          this.external_user_id = json.serialize(email);
          }
          this.first_name = json.serialize(first_name);
          this.last_name = json.serialize(last_name);
          this.models = json.serialize(models);
          this.permissions = json.serialize(permissions);
          this.access_filters = json.serialize(access_filters);
        }
    }
    
    public class UCLookerUrl {
        UCLookerInstance looker_instance {get;set;}
        UCLookerUser user {get;set;}
        string current_time {get;set;}
        string path {get;set;}
        string session_length {get;set;}
        string force_logout_login {get;set;}
        string nonce {get;set;}
        string signature {get;set;}
        
        public UCLookerUrl(UCLookerUser user, UCLookerInstance looker_instance, integer session_length, string embed_url, boolean force_logout_login){
            this.looker_instance = looker_instance;
            this.user = user;
            this.path = '/login/embed/' + EncodingUtil.urlEncode(embed_url, 'UTF-8');
            this.session_length = String.valueOf(session_length);
            this.force_logout_login = String.valueOf(force_logout_login);
        }
        
        private String generateRandomString(Integer len) {
            final String chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz';
            String randStr = '';
            while (randStr.length() < len) {
               Integer idx = Math.mod(Math.abs(Crypto.getRandomInteger()), chars.length());
               randStr += chars.substring(idx, idx+1);
            }
            return randStr; 
            //return '123456789';
        }
        
        private string sign(){
            string string_to_sign = '';
            string_to_sign = string_to_sign + this.looker_instance.host   + '\n';
            string_to_sign = string_to_sign + this.path           + '\n';
            string_to_sign = string_to_sign + this.nonce          + '\n';
            string_to_sign = string_to_sign + this.current_time       + '\n';
            string_to_sign = string_to_sign + this.session_length       + '\n';
            string_to_sign = string_to_sign + this.user.external_user_id  + '\n';
            string_to_sign = string_to_sign + this.user.permissions     + '\n';
            string_to_sign = string_to_sign + this.user.models        + '\n';
            string_to_sign = string_to_sign + this.user.access_filters;
            Blob encrypted_string_to_sign = Crypto.generateMac('HMacSHA1',Blob.valueOf(string_to_sign),Blob.valueOf(this.looker_instance.secret)); 
          string signature = EncodingUtil.base64Encode(encrypted_string_to_sign);
            return signature;
        }
        
        
        public string generateUrl(){
            this.nonce = json.serialize(generateRandomString(16));
            this.current_time = json.serialize(datetime.now().getTime()/1000);
            this.signature = this.sign();
            string query_string = '';
            query_string = query_string + 'nonce=' + EncodingUtil.urlEncode(this.nonce,'UTF-8');
            query_string = query_string + '&time=' + EncodingUtil.urlEncode(this.current_time,'UTF-8');
            query_string = query_string + '&session_length=' + EncodingUtil.urlEncode(this.session_length,'UTF-8');
            query_string = query_string + '&external_user_id=' + EncodingUtil.urlEncode(this.user.external_user_id,'UTF-8');
            query_string = query_string + '&permissions=' + EncodingUtil.urlEncode(this.user.permissions,'UTF-8');
            query_string = query_string + '&models=' + EncodingUtil.urlEncode(this.user.models,'UTF-8');
            query_string = query_string + '&access_filters=' + EncodingUtil.urlEncode(this.user.access_filters,'UTF-8');
            query_string = query_string + '&signature=' + EncodingUtil.urlEncode(this.signature,'UTF-8');
            query_string = query_string + '&first_name=' + EncodingUtil.urlEncode(this.user.first_name,'UTF-8');
            query_string = query_string + '&last_name=' + EncodingUtil.urlEncode(this.user.last_name,'UTF-8');
            query_string = query_string + '&force_logout_login=' + EncodingUtil.urlEncode(this.force_logout_login,'UTF-8');
            return 'https://' + this.looker_instance.host + this.path + '?' + query_string;
        }
        
    }
    
    public String getGenerateIframeUrl() {
        UCLookerInstance looker = new UCLookerInstance(this.looker_host, this.looker_secret);
        UCLookerUser user = new UCLookerUser(null,UserInfo.getFirstName(), UserInfo.getLastName(), this.looker_models.split(','), this.looker_permissions.split(','), json.deserializeUntyped(this.looker_access_filters.replaceAll('\'', '"')));
        UCLookerUrl url = new UCLookerUrl(user, looker, (24 * 60 * 60), this.embed_path, true);
        return url.generateUrl();
    }
    
}

/* This is Test Module */
@isTest
private class UCEmbedLookerControllerTest {
    
    static testMethod void testGetGenerateIframeUrl(){

    UCEmbedLookerController cntrl = new UCEmbedLookerController();
        cntrl.embed_path = 'a';
        cntrl.looker_access_filters = '{"test":1}';
        cntrl.looker_models = 'test';
        cntrl.looker_permissions = 'test';
        cntrl.getGenerateIframeUrl();
        
    }

}