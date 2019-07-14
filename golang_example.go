package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Request struct {
   Secret string   //required
   Host string     //required
   EmbedURL string //required
   Nonce  string  //required
   Time int64       //required
   SessionLength int    //required
   ExternalUserId string   //required
   Permissions []string   //required
   Models []string        //required
   ForceLogout bool    //required
   GroupsIds []int     //optional
   ExternalGroupId string   //optional
   UserAttributes map[string]interface{}   //optional
   AccessFilters map[string]map[string]interface{}  //required
   FirstName string //optional
   LastName string //optional

}

// TODO: Replace with your own nonce algorithm
func MakeNonce() string {
	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	b := make([]rune, 16)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}

	str := string(b)
	str2, _ := json.Marshal([]byte(str))
	return string(str2)
}

func (r *Request) SignRequest() string {

	jsonPerms, _ := json.Marshal(r.Permissions)
	jsonModels, _ := json.Marshal(r.Models)
	jsonUserAttrs, _ := json.Marshal(r.UserAttributes)
	jsonFilters, _ := json.Marshal(r.AccessFilters)
	jsonGroupIds, _ := json.Marshal(r.GroupsIds)
	strTime := strconv.Itoa(int(r.Time))
	strSessionLen := strconv.Itoa(r.SessionLength)
	strForceLogin := strconv.FormatBool(r.ForceLogout)

	strToSign := strings.Join([]string{r.Host,
		                               r.EmbedURL,
		                               r.Nonce,
		                               strTime,
		                               strSessionLen,
		                               r.ExternalUserId,
		                               string(jsonPerms),
		                               string(jsonModels)},"\n")

	strToSign = strToSign + "\n"

	if len(r.GroupsIds) > 0 {
		strToSign = strToSign + string(jsonGroupIds) + "\n"
	}

	if r.ExternalGroupId != "" {
		strToSign = strToSign + r.ExternalGroupId + "\n"
	}

	if len(r.UserAttributes) > 0 {
		strToSign = strToSign + string(jsonUserAttrs) + "\n"
	}

	strToSign = strToSign + string(jsonFilters)

	h := hmac.New(sha1.New,[]byte(r.Secret))
	h.Write([]byte(strToSign))
	encoded := base64.StdEncoding.EncodeToString(h.Sum(nil))

	query := url.Values{}
	query.Add("nonce",r.Nonce)
	query.Add("time",strTime)
	query.Add("session_length",strSessionLen)
	query.Add("external_user_id",r.ExternalUserId)
	query.Add("permissions",string(jsonPerms))
	query.Add("models",string(jsonModels))
	query.Add("access_filters",string(jsonFilters))
	query.Add("first_name",r.FirstName)
	query.Add("last_name",r.LastName)
	query.Add("force_logout_login",strForceLogin)
	query.Add("signature",encoded)

	if len(r.GroupsIds) > 0 {
		query.Add("group_ids",string(jsonGroupIds))
	}

	if r.ExternalGroupId != "" {
		query.Add("external_group_id",r.ExternalGroupId)
	}

    if len(r.UserAttributes) > 0 {
    	query.Add("user_attributes",string(jsonUserAttrs))
	}

	finalUrl := fmt.Sprintf("https://%s%s?%s",r.Host,r.EmbedURL,query.Encode())

	return finalUrl
}

func main() {

	// Update with your embed secret
	secret := "Your secret here"

	// Update this function to customize your nonce
	nonce := MakeNonce()

	// Your looker host
	host := "demo.looker.com"

	// Change this to the ID of your look
	lookPath := "/embed/looks/1"

	// Current time
	currentTime := time.Now().Unix()

	// Session Length
	sessLength := 3600

	// ExternalUserId
	externalUserId := "0"

	// Permissions for the look or dashboard
	perms := []string{"access_data","see_looks"}

	// Models this embed has access to
	models :=  []string{"mymodel"}

	// Whether to force logout
	forceLogout := false

	// Group IDS
	groupIds := make([]int,0)

	// External Group Id
	externalGroupId := ""

	// Add any user attributes here
	attrs := make(map[string]interface{})

	// Add any filters here
	filters := make(map[string]map[string]interface{})

	// First Name
	firstName := ""

	// Last Name
	lastName := ""

	r := Request{
		Secret: secret,
		Nonce: nonce,
		Host: host,
		EmbedURL:  "/login/embed/" + url.QueryEscape(lookPath),
		Time: currentTime,
		SessionLength: sessLength,
		ExternalUserId: externalUserId,
		Permissions: perms,
		Models: models,
		ForceLogout: forceLogout,
		GroupsIds: groupIds,
		ExternalGroupId: externalGroupId,
        UserAttributes: attrs,
        AccessFilters:  filters,
        FirstName: firstName,
        LastName: lastName,
	}

	s := r.SignRequest()

	fmt.Printf("Embed URL: %s\n",s)
}

