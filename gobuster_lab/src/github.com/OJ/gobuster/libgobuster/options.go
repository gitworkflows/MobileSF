package libgobuster

import (
	"fmt"
	"os"
	"regexp"
	"bufio"
	"strconv"
	"strings"
	"time"

	multierror "github.com/hashicorp/go-multierror"
)

// Options helds all options that can be passed to libgobuster
type Options struct {
	Password          string
	Threads           int
	URL               string
	UserAgent         string
	Username          string
	Wordlist          string
	Proxy             string
	JsonOut			  string
	Cookies           string
	Timeout           time.Duration
	FollowRedirect    bool
	IncludeLength     bool
	NoStatus          bool
	NoProgress        bool
	Expanded          bool
	Quiet             bool
	InsecureSSL       bool
	WildcardForced    bool
	Verbose           bool
	HashTresh	      int
	EditTresh	      float64
	EditHashTresh     int
	EditHashTreshI    int
	IsInit		      bool
	Tuning		      string
	VariablesPath     string
	Variables         map[string][]string 
	VariableExp		  *regexp.Regexp
	TestList		  map[string]string

}

// NewOptions returns a new initialized Options object
func NewOptions() *Options {
	return &Options{}
}

// Validate validates the given options
func (opt *Options) validate() *multierror.Error {
	var errorList *multierror.Error

	if opt.Threads < 0 {
		errorList = multierror.Append(errorList, fmt.Errorf("[!] Threads (-t): Invalid value: %d", opt.Threads))
	}

	if opt.Wordlist == "" {
		errorList = multierror.Append(errorList, fmt.Errorf("[!] [!] WordList (-w): Must be specified (use `-w -` for stdin)"))
	} else if opt.Wordlist == "-" {
		// STDIN
	} else if _, err := os.Stat(opt.Wordlist); os.IsNotExist(err) {
		errorList = multierror.Append(errorList, fmt.Errorf("Wordlist (-w): File does not exist: %s", opt.Wordlist))
	}

	if opt.URL == "" {
		errorList = multierror.Append(errorList, fmt.Errorf("[!] Url/Domain (-u): Must be specified"))
	}

	if opt.VariablesPath == "" {
		errorList = multierror.Append(errorList, fmt.Errorf("[!] Nikto variables file (-V): Must be specified"))
	}
	if opt.URL != ""{
		if !strings.HasSuffix(opt.URL, "/") {
			opt.URL = fmt.Sprintf("%s/", opt.URL)
		}
	}

	return errorList
}

func (o *Options) ParseVariables() {
		
	o.Variables = make(map[string][]string)

	vars, err := os.Open(o.VariablesPath)
	Check("Error parsing opening file: ", err)
	defer vars.Close()
	scanner := bufio.NewScanner(vars)

	for scanner.Scan() {
		
		word := strings.TrimSpace(scanner.Text())
		match, _ := regexp.MatchString("@[A-Z0-9]*=(\\S*\\s)*", word)
		if !match{
			fmt.Fprintf(os.Stderr, "Error parsing variable file on line: %s\n",word)
			os.Exit(1)
		}
		// Skip "comment" (starts with #), as well as empty lines
		if !strings.HasPrefix(word, "#") && len(word) > 0 {
			parts := strings.Split(word, "=")
			uris := strings.Split(parts[1], " ")
			o.Variables[parts[0]] = uris
		}
	}
	varExp := "Id0ntEx1sT"
	for key, _ := range o.Variables{
		varExp = varExp + "|" + key
	}
	o.VariableExp = regexp.MustCompile(varExp)
}

func (opt *Options) validateURL() error {

	if !strings.HasPrefix(opt.URL, "http") {
		// check to see if a port was specified
		re := regexp.MustCompile(`^[^/]+:(\d+)`)
		match := re.FindStringSubmatch(opt.URL)

		if len(match) < 2 {
			// no port, default to http on 80
			opt.URL = fmt.Sprintf("http://%s", opt.URL)
		} else {
			port, err := strconv.Atoi(match[1])
			if err != nil || (port != 80 && port != 443) {
				return fmt.Errorf("[!] url scheme not specified")
			} else if port == 80 {
				opt.URL = fmt.Sprintf("http://%s", opt.URL)
			} else {
				opt.URL = fmt.Sprintf("https://%s", opt.URL)
			}
		}
	}

	if opt.Username != "" && opt.Password == "" {
		return fmt.Errorf("[!] username was provided but password is missing")
	}

	return nil
}
