package libgobuster

import (
	"context"
	"crypto/tls"
	"os"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"regexp"
	"strconv"
	"unicode/utf8"
	"github.com/glaslos/ssdeep"
)

type httpClient struct {
	client        *http.Client
	context       context.Context
	userAgent     string
	username      string
	password      string
	includeLength bool
}

// NewHTTPClient returns a new HTTPClient
func NewHTTPClient(c context.Context, opt *Options) (*httpClient, error) {
	var proxyURLFunc func(*http.Request) (*url.URL, error)
	var client httpClient
	proxyURLFunc = http.ProxyFromEnvironment

	if opt == nil {
		return nil, fmt.Errorf("[!] options is nil")
	}

	if opt.Proxy != "" {
		proxyURL, err := url.Parse(opt.Proxy)
		if err != nil {
			return nil, fmt.Errorf("[!] proxy URL is invalid (%v)", err)
		}
		proxyURLFunc = http.ProxyURL(proxyURL)
	}

	var redirectFunc func(req *http.Request, via []*http.Request) error
	if !opt.FollowRedirect {
		redirectFunc = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else {
		redirectFunc = nil
	}

	client.client = &http.Client{
		Timeout:       opt.Timeout,
		CheckRedirect: redirectFunc,
		Transport: &http.Transport{
			Proxy: proxyURLFunc,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opt.InsecureSSL,
			},
		}}
	client.context = c
	client.username = opt.Username
	client.password = opt.Password
	client.includeLength = opt.IncludeLength
	client.userAgent = opt.UserAgent
	return &client, nil
}

/*
This function implement checks if a a response is positive to a nikto test
It implements the logic behind nikto tests
*/

func NiktoTest( g *Gobuster, matches [5]*regexp.Regexp, is_status [5]bool, body string, status_code string, word []string)(bool){

	var res [5]bool

	for i := 0; i < 5; i++ {
		if matches[i] != nil{
			if is_status[i] {
				res[i] = matches[i].MatchString(status_code)
			}else{
				res[i] = matches[i].MatchString(body)
			}
		}else {
			if i == 2{
				res[i] = true
			} else{
				res[i] = false
			}
		}		
	}
	if matches[0] == nil && matches[1] == nil{
		res[0] = true
	}
	
	return (res[0] || res[1]) && res[2] && !res[3] && !res[4]
}

func CreateNiktoExpression(word []string)([5]*regexp.Regexp, [5]bool){
	var errors [5]error
	var matches [5]*regexp.Regexp
	var wordIndex = 5
	var statusCodeInExp [5]bool
	var statuscode_exp = regexp.MustCompile("[0-9]{3}")

	for i := 0; i < 5; i++ {
		if word[wordIndex] != "" {
			// check if the expression is a status code
			status := statuscode_exp.MatchString(word[wordIndex])
			if status {
				statusCodeInExp[i] = true
			}
			// compile the expression
			matches[i], errors[i] = regexp.Compile(word[wordIndex])
			if errors[i] != nil{
				fmt.Fprintf(os.Stderr,"[!] Failure to compile nikto expression: "); fmt.Fprintf(os.Stderr, "%s\n",errors[i]); 
				matches[i] = nil
			}
		}
		wordIndex ++;
	}
	return matches, statusCodeInExp
}

func setHeaders(headers string, req *http.Request){
	var head = strings.Split(headers, ":")
		var val string
		param := head[0]
		if len(head) < 2{
			val = ""
		} else {
			val = head[1]
		}
		req.Header.Set(param,val)
}

func getBodyLenght(body []byte, err error, resp *http.Response)(*int64){
	var length *int64 = nil
	length = new(int64)
	if resp.ContentLength <= 0 {
		if err == nil {
			*length = int64(utf8.RuneCountInString(string(body)))
		}
	} else {
		*length = resp.ContentLength
	}
	return length
}
// Make a request to the given URL and check if positive to the test
func (client *httpClient) MakeRequestNik(g *Gobuster, fullUrl, cookie string, word []string) (*int, *int64, bool, string, string, bool) {

	var goodHeadersExp = regexp.MustCompile("text/|application/")
	var positive = false
	var httpMethod = word[4]
	var httpData = word[11]
	var headers = word[12]
	var data io.Reader
	var niktoExp [5]*regexp.Regexp
	var niktoExpStatusCode [5]bool

	niktoExp, niktoExpStatusCode = CreateNiktoExpression(word)
	
	//Set httpData
	if httpData != ""{
		data = strings.NewReader(httpData)
	} else{
		data = nil
	}
	req, err := http.NewRequest(httpMethod, fullUrl, data)

	if err != nil || g.Interrupted{
		return nil, nil, false, "", "", true
	}

	// add the context so we can easily cancel out
	req = req.WithContext(client.context)

	// Parse and set request headers
	if headers != ""{
		setHeaders(headers,req)	
	}

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	if client.userAgent != "" {
		req.Header.Set("User-Agent", client.userAgent)
	}

	req.Header.Set("Connection", "Keep-Alive")

	if client.username != "" {
		req.SetBasicAuth(client.username, client.password)
	}

	resp, err := client.client.Do(req)
	if err != nil {

		if g.Opts.Verbose && !g.Interrupted{
			fmt.Fprintf(os.Stderr,"[!] Response error for %s:\n  --> %s\n",fullUrl,err)

		}
		if ue, ok := err.(*url.Error); ok {
			if strings.HasPrefix(ue.Err.Error(), "x509") && !g.Opts.Quiet{
				fmt.Fprintf(os.Stderr,"[!] Invalid certificate\n")
			}
		}
		if resp != nil{
			return &resp.StatusCode, nil, false, "", "", true
		}
		bad_status := 999
		return &bad_status, nil, false, "", "",true

	}

	if len(resp.Header["Content-Type"]) > 0{
		respHeaders := goodHeadersExp.MatchString(resp.Header["Content-Type"][0]);
		if !respHeaders {
			return &resp.StatusCode, nil, false, "", "",false
		}
	}
	// Read body
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)	

	// Compute body length
	length := getBodyLenght(body, err, resp)
	
	// Nikto test 
	positive = NiktoTest(g, niktoExp, niktoExpStatusCode, string(body[:]), strconv.Itoa(resp.StatusCode),word)
	
	var hash = ""
	var content = ""

	if positive || g.Opts.IsInit{
		//Store first 100 bytes of response body
		if int(*length) <= g.Opts.EditHashTresh{
			content = string(body[:int(*length)])
		}else{
			content = string(body[:(g.Opts.EditHashTresh-3)]) + "..."
		}
		// For big responses calculate the FuzzHash
		if int(*length) > g.Opts.EditHashTresh{
			hash, _ = ssdeep.FuzzyReader(strings.NewReader(string(body[:])),int(*length))
		}else{
				hash = ""
		}

	}
	return &resp.StatusCode, length, positive, hash, content, false
}

// MakeRequest makes a request to the specified url
func (client *httpClient) makeRequest(fullURL, cookie string) (*int, *int64, error) {
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)

	if err != nil {
		return nil, nil, err
	}

	// add the context so we can easily cancel out
	req = req.WithContext(client.context)

	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}

	ua := fmt.Sprintf("gobuster %s", VERSION)
	if client.userAgent != "" {
		ua = client.userAgent
	}
	req.Header.Set("User-Agent", ua)

	if client.username != "" {
		req.SetBasicAuth(client.username, client.password)
	}

	resp, err := client.client.Do(req)
	if err != nil {
		if ue, ok := err.(*url.Error); ok {

			if strings.HasPrefix(ue.Err.Error(), "x509") {
				return nil, nil, fmt.Errorf("[!] Invalid certificate: %v", ue.Err)
			}
		}
		return nil, nil, err
	}

	defer resp.Body.Close()

	var length *int64

	if client.includeLength {
		length = new(int64)
		if resp.ContentLength <= 0 {
			body, err2 := ioutil.ReadAll(resp.Body)
			if err2 == nil {
				*length = int64(utf8.RuneCountInString(string(body)))
			}
		} else {
			*length = resp.ContentLength
		}
	} else {
		// DO NOT REMOVE!
		// absolutely needed so golang will reuse connections!
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return nil, nil, err
		}
	}

	return &resp.StatusCode, length, nil
}
