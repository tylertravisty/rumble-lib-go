package rumble

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"github.com/robertkrimen/otto"
)

const (
	domain                 = "rumble.com"
	urlBase                = "https://" + domain
	urlAccount             = urlBase + "/account"
	urlService             = urlBase + "/service.php?name="
	urlServiceUserGetSalts = urlService + "user.get_salts"
	urlServiceUserLogin    = urlService + "user.login"
	urlServiceUserLogout   = urlService + "user.logout"
)

type Client struct {
	httpClient *http.Client
}

type NewClientOptions struct {
	Cookies []*http.Cookie
}

func NewClient(opts NewClientOptions) (*Client, error) {
	cl, err := newHttpClient(opts.Cookies)
	if err != nil {
		return nil, pkgErr("error creating new http client: %v", err)
	}

	return &Client{httpClient: cl}, nil
}

func newHttpClient(cookies []*http.Cookie) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("error creating cookiejar: %v", err)
	}

	url, err := url.Parse(urlBase)
	if err != nil {
		return nil, fmt.Errorf("error parsing url: %v", err)
	}
	jar.SetCookies(url, cookies)

	return &http.Client{Jar: jar}, nil
}

func (c *Client) Login(username string, password string) ([]*http.Cookie, error) {
	if c.httpClient == nil {
		return nil, pkgErr("", fmt.Errorf("http client is nil"))
	}

	salts, err := c.getSalts(username)
	if err != nil {
		return nil, pkgErr("error getting salts: %v", err)
	}

	cookies, err := c.login(username, password, salts)
	if err != nil {
		return nil, pkgErr("error logging in", err)
	}

	return cookies, nil
}

type GetSaltsData struct {
	Salts []string `json:"salts"`
}

type GetSaltsResponse struct {
	Data GetSaltsData `json:"data"`
}

func (c *Client) getSalts(username string) ([]string, error) {
	u := url.URL{}
	q := u.Query()
	q.Add("username", username)
	body := q.Encode()

	resp, err := c.httpClient.Post(urlServiceUserGetSalts, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http post request returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http post response status not %s: %s", http.StatusText(http.StatusOK), resp.Status)
	}

	bodyB, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var gsr GetSaltsResponse
	err = json.NewDecoder(strings.NewReader(string(bodyB))).Decode(&gsr)
	if err != nil {
		return nil, fmt.Errorf("error decoding response body: %v", err)
	}

	return gsr.Data.Salts, nil
}

func (c *Client) login(username string, password string, salts []string) ([]*http.Cookie, error) {
	hashes, err := hash(password, salts)
	if err != nil {
		return nil, fmt.Errorf("error generating password hashes: %v", err)
	}

	u := url.URL{}
	q := u.Query()
	q.Add("username", username)
	q.Add("password_hashes", hashes)
	body := q.Encode()
	resp, err := c.httpClient.Post(urlServiceUserLogin, "application/x-www-form-urlencoded", strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("http post request returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http post response status not %s: %s", http.StatusText(http.StatusOK), resp.Status)
	}

	bodyB, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	session, err := loginSession(bodyB)
	if err != nil {
		return nil, fmt.Errorf("error getting login session: %v", err)
	}

	if session == "false" {
		return nil, fmt.Errorf("failed to log in ")
	}

	return resp.Cookies(), nil
}

func hash(password string, salts []string) (string, error) {
	vm := otto.New()

	vm.Set("password", password)
	vm.Set("salt0", salts[0])
	vm.Set("salt1", salts[1])
	vm.Set("salt2", salts[2])

	_, err := vm.Run(md5)
	if err != nil {
		return "", fmt.Errorf("error running md5 javascript: %v", err)
	}

	hashesV, err := vm.Get("hashes")
	if err != nil {
		return "", fmt.Errorf("error getting hashes: %v", err)
	}

	hashesS, err := hashesV.ToString()
	if err != nil {
		return "", fmt.Errorf("error converting hashes value to string: %v", err)
	}

	return hashesS, nil
}

type LoginSessionDataBool struct {
	Session bool `json:"session"`
}

type LoginSessionBool struct {
	Data LoginSessionDataBool `json:"data"`
}

type LoginSessionDataString struct {
	Session string `json:"session"`
}

type LoginSessionString struct {
	Data LoginSessionDataString `json:"data"`
}

func loginSession(body []byte) (string, error) {
	bodyS := string(body)

	var lss LoginSessionString
	err := json.NewDecoder(strings.NewReader(bodyS)).Decode(&lss)
	if err == nil {
		return lss.Data.Session, nil
	}

	var lsb LoginSessionBool
	err = json.NewDecoder(strings.NewReader(bodyS)).Decode(&lsb)
	if err == nil {
		return "false", nil
	}

	return "", fmt.Errorf("error decoding response body")
}

func (c *Client) Logout() error {
	if c.httpClient == nil {
		return pkgErr("", fmt.Errorf("http client is nil"))
	}

	err := c.logout()
	if err != nil {
		return pkgErr("error logging out", err)
	}

	return nil
}

func (c *Client) logout() error {
	resp, err := c.httpClient.Get(urlServiceUserLogout)
	if err != nil {
		return fmt.Errorf("http get request returned error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http get response status not %s: %s", http.StatusText(http.StatusOK), resp.Status)
	}

	return nil
}

type LoggedInResponseUser struct {
	LoggedIn bool `json:"logged_in"`
}

type LoggedInResponse struct {
	User LoggedInResponseUser `json:"user"`
}

func (c *Client) LoggedIn() (bool, error) {
	resp, err := c.httpClient.Get(urlServiceUserLogin)
	if err != nil {
		return false, pkgErr("http get request returned error", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("http get response status not %s: %s", http.StatusText(http.StatusOK), resp.Status)
	}

	bodyB, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, pkgErr("error reading response body", err)
	}

	var lir LoggedInResponse
	err = json.NewDecoder(strings.NewReader(string(bodyB))).Decode(&lir)
	if err != nil {
		return false, pkgErr("error un-marshaling response body", err)
	}

	return lir.User.LoggedIn, nil
}
