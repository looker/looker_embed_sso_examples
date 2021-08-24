// See https://docs.looker.com/reference/embedding/sso-embed
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// URLParams is the input for the embedded URL creation.
type URLParams struct {
	Host             string // The looker instance e.g. acmeincinstance.cloud.looker.com
	Path             string
	ExternalUserID   string
	ExternalGroupID  string
	FirstName        string
	LastName         string
	Models           []string
	Permissions      []string
	SessionLength    int
	GroupIDs         []int64 // The Looker Group Ids
	UserAttributes   map[string]string
	ForceLogoutLogin bool
}

// NewURLParams Returns an empty URLParams
func NewURLParams() *URLParams {
	return &URLParams{
		UserAttributes: make(map[string]string),
	}
}

func (p *stringifiedURLParams) sign(secret, nonce, msecsSinceEpochStr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", p.Host)
	fmt.Fprintf(&b, "%s\n", p.Path)
	fmt.Fprintf(&b, "\"%s\"\n", nonce)
	fmt.Fprintf(&b, "%s\n", msecsSinceEpochStr)
	fmt.Fprintf(&b, "%s\n", p.SessionLength)
	fmt.Fprintf(&b, "%s\n", p.ExternalUserID)
	fmt.Fprintf(&b, "%s\n", p.Permissions)
	fmt.Fprintf(&b, "%s\n", p.Models)
	fmt.Fprintf(&b, "%s\n", p.GroupIDs)
	fmt.Fprintf(&b, "%s\n", p.ExternalGroupID)
	fmt.Fprintf(&b, "%s\n", p.UserAttributes)
	fmt.Fprintf(&b, "{}") // deprecated access_filters but still needed

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write([]byte(b.String()))
	bytesMac := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(bytesMac)
}

// CreateLookerSSOEmbeddedHostnameAndPath creates and returns a signed URL that is valid for expireInSecs seconds
func (p *URLParams) CreateLookerSSOEmbeddedHostnameAndPath(key string, expiresAfter time.Duration) (string, error) {
	if expiresAfter > 5*time.Minute {
		return "", fmt.Errorf("the expiration time has to be less than 5 minutes, was %v", expiresAfter)
	}
	nonce, err := randomString()
	if err != nil {
		return "", err
	}

	// By default looker makes the URL expire after 5 minutes. We can decease this by removing
	// time from the secsSinceEpoch we send the server
	secsSinceEpoch := (time.Now().Add(-(5*time.Minute - expiresAfter))).Unix()
	secsSinceEpochStr := strconv.FormatInt(secsSinceEpoch, 10)

	strParams, err := newStringifiedURLParams(p)
	if err != nil {
		return "", err
	}

	signature := strParams.sign(key, nonce, secsSinceEpochStr)

	params := url.Values{}
	params.Add("nonce", "\""+nonce+"\"")
	params.Add("time", secsSinceEpochStr)
	params.Add("session_length", strParams.SessionLength)
	params.Add("external_user_id", strParams.ExternalUserID)
	params.Add("external_group_id", strParams.ExternalGroupID)
	params.Add("permissions", strParams.Permissions)
	params.Add("models", strParams.Models)
	params.Add("access_filters", "{}")
	params.Add("signature", signature)
	params.Add("first_name", strParams.FirstName)
	params.Add("last_name", strParams.LastName)
	params.Add("group_ids", strParams.GroupIDs)
	params.Add("user_attributes", strParams.UserAttributes)
	params.Add("force_logout_login", strParams.ForceLogoutLogin)

	return strParams.Host + strParams.Path + "?" + params.Encode(), nil
}

func randomString() (string, error) {
	const length = 16
	bytes := make([]byte, length)
	bytesReadLen, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	if bytesReadLen != length {
		return "", fmt.Errorf("random did not return all bytes")
	}

	return hex.EncodeToString(bytes), nil
}

type stringifiedURLParams struct {
	Host             string
	Path             string
	ExternalUserID   string
	ExternalGroupID  string
	FirstName        string
	LastName         string
	Models           string
	Permissions      string
	SessionLength    string
	GroupIDs         string
	UserAttributes   string
	ForceLogoutLogin string
}

func newStringifiedURLParams(p *URLParams) (*stringifiedURLParams, error) {
	marshalledExternalUserID, err := json.Marshal(p.ExternalUserID)
	if err != nil {
		return nil, err
	}
	marshalledExternalGroupID, err := json.Marshal(p.ExternalGroupID)
	if err != nil {
		return nil, err
	}
	marshalledFirstName, err := json.Marshal(p.FirstName)
	if err != nil {
		return nil, err
	}
	marshalledLastName, err := json.Marshal(p.LastName)
	if err != nil {
		return nil, err
	}
	marshalledPermissions, err := json.Marshal(p.Permissions)
	if err != nil {
		return nil, err
	}
	marshalledGroupIds, err := json.Marshal(p.GroupIDs)
	if err != nil {
		return nil, err
	}
	marshalledUserAttributes, err := json.Marshal(p.UserAttributes)
	if err != nil {
		return nil, err
	}
	marshalledModels, err := json.Marshal(p.Models)
	if err != nil {
		return nil, err
	}
	rr := &stringifiedURLParams{
		p.Host,
		"/login/embed/" + url.PathEscape(p.Path),
		string(marshalledExternalUserID),
		string(marshalledExternalGroupID),
		string(marshalledFirstName),
		string(marshalledLastName),
		string(marshalledModels),
		string(marshalledPermissions),
		fmt.Sprintf("%d", p.SessionLength),
		string(marshalledGroupIds),
		string(marshalledUserAttributes),
		"true",
	}
	if p.ForceLogoutLogin {
		rr.ForceLogoutLogin = "true"
	} else {
		rr.ForceLogoutLogin = "false"
	}

	return rr, nil
}

func main() {
	foo := &URLParams{
		Host:             "acmeincinstance.cloud.looker.com",
		Path:             "/embed/dashboards-next/47",
		ExternalUserID:   "username@acmeinc",
		ExternalGroupID:  "acmeinc",
		Models:           []string{"acmeinc"},
		GroupIDs:         []int64{70},
		SessionLength:    24 * 60 * 60,
		Permissions:      []string{"access_data", "see_user_dashboards", "see_lookml_dashboards", "see_looks"},
		UserAttributes:   map[string]string{},
		ForceLogoutLogin: true,
	}

	res, err := foo.CreateLookerSSOEmbeddedHostnameAndPath("SECRET", time.Minute)
	if err != nil {
		println("failed to create Embedded URL %v", err)
		os.Exit(1)
	}

	// This is the URL to try at Looker console
	fmt.Printf("https://%s\n", res)
}