package libgobuster

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"context"
	"fmt"
	"os"
	"io"
	"strings"
	"sync"
)

const (
	// VERSION contains the current gobuster version
	VERSION = "2.0.1"
)

// SetupFunc is the "setup" function prototype for implementations
type SetupFunc func(*Gobuster) error

// ProcessFunc is the "process" function prototype for implementations
type ProcessFunc func(*Gobuster, []string) ([]Result, error, int, int)

// ResultToStringFunc is the "to string" function prototype for implementations
type ResultToStringFunc func(*Gobuster, *Result) (*string, error)


type JsonOutput struct {
	Code	int
	Paths	[]string
}

// Gobuster is the main object when creating a new run
type Gobuster struct {
	Opts             *Options
	http             *httpClient
	WildcardIps      stringSet
	context          context.Context
	requestsExpected int
	requestsIssued   int
	failsRatio			 int
	mu               *sync.RWMutex
	plugin           GobusterPlugin
	IsWildcard       bool
	Interrupted		 bool
	IsReachable		 bool
	Wildcards404     [3]string
	WildcardsContent404     [3]string
	resultChan       chan Result
	errorChan        chan error
	JsonResult       map[string]int
}

// GobusterPlugin is an interface which plugins must implement
type GobusterPlugin interface {
	Setup(*Gobuster) error
	Process(*Gobuster, []string) ([]Result, error, int, int)
	ResultToString(*Gobuster, *Result) (*string, error)
}

// NewGobuster returns a new Gobuster object
func NewGobuster(c context.Context, opts *Options, plugin GobusterPlugin) (*Gobuster, error) {
	// validate given options
	multiErr := opts.validate()
	if multiErr != nil {
		return nil, multiErr
	}

	var g Gobuster
	opts.ParseVariables()

	g.WildcardIps = newStringSet()
	g.context = c
	g.Opts = opts
	h, err := NewHTTPClient(c, opts)
	if err != nil {
		return nil, err
	}
	g.http = h

	g.plugin = plugin
	g.mu = new(sync.RWMutex)

	g.resultChan = make(chan Result)
	g.errorChan = make(chan error)

	return &g, nil
}

func (g *Gobuster)NewContext(c context.Context){
	g.context = c
}
func (g *Gobuster)NewHttp(h *httpClient){
	g.http = h
}

// Results returns a channel of Results
func (g *Gobuster) Results() <-chan Result {
	return g.resultChan
}

// Errors returns a channel of errors
func (g *Gobuster) Errors() <-chan error {
	return g.errorChan
}

func (g *Gobuster) incrementRequests(req int) {
	g.mu.Lock()
	g.requestsIssued = g.requestsIssued + req
	g.requestsExpected = g.requestsExpected + (req - 1) 
	g.mu.Unlock()
}

func (g *Gobuster) incrementFails(increment int ) {
	g.mu.Lock()
	g.failsRatio = g.failsRatio + increment
	if g.failsRatio < 0{
		g.failsRatio = 0 
	}
	g.mu.Unlock()
}

func (g *Gobuster)BuildUrl(uri string )(string){	
	if strings.HasPrefix(uri, "/") == true {
		uri = uri[1:]
	}
	return g.Opts.URL+uri
}
// PrintProgress outputs the current wordlist progress to stderr
func (g *Gobuster) PrintProgress() {
	if !g.Opts.Quiet && !g.Opts.NoProgress {
		g.mu.RLock()
		if g.requestsExpected > 0 {
			fmt.Fprintf(os.Stdout, "\rProgress: %d / %d (%3.2f%%)", g.requestsIssued, g.requestsExpected, float32(g.requestsIssued)*100.0/float32(g.requestsExpected))
		}
		g.mu.RUnlock()
	}
}

// ClearProgress removes the last status line from stderr
func (g *Gobuster) ClearProgress() {
	fmt.Fprint(os.Stderr, resetTerminal())
}

// GetRequest issues a GET request to the target and returns
// the status code, length and an error
func (g *Gobuster) GetRequest(url string) (*int, *int64, error) {
	return g.http.makeRequest(url, g.Opts.Cookies)
}
// GetRequest issues a GET request to the target in nikto formatand returns
// the status code, length and an error
func (g *Gobuster) GetRequestNik(url string,cookie string, word []string) (*int, *int64, bool, string, string, bool) {
	if g.Opts.Verbose{
		fmt.Fprintf(os.Stdout, "[i] request to: %s\n", url)
	}
	if word != nil {
		return g.http.MakeRequestNik(g, url, cookie, word)
	} else {
		word := []string{"", "", "", "", "GET", "200", "", "", "", "", "", "", ""}
		return g.http.MakeRequestNik(g, url, cookie, word)
	}
}

func (g *Gobuster) worker(wordChan <-chan []string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-g.context.Done():
			return
		case word, ok := <-wordChan:
			// worker finished
			if !ok {
				return
			}
			// Mode-specific processing
			res, err, fails, success := g.plugin.Process(g, word)
			g.incrementRequests(fails+success)
			g.incrementFails(fails-success)
			if err != nil && err.Error() != "NoResult"{
				// do not exit and continue
				g.errorChan <- err
				continue
			} else {
				for _, r := range res {
					if err == nil {
						g.resultChan <- r
					}
				}
			}
		}
	}
}

// Read a create a new reader for the input wordlist
func (g *Gobuster) getWordlist() (*csv.Reader, error) {

	// Pull content from the wordlist
	wordlist, err := os.Open(g.Opts.Wordlist)
	Check("Failed to open wordlist: ",err)

	lines, err := lineCounter(wordlist)
	Check("Failed to get number of lines: ",err)

	g.requestsExpected = lines
	g.requestsIssued = 0

	// rewind wordlist
	_, err = wordlist.Seek(0, 0)
	Check("Failed to rewind wordlist: ", err)

	return csv.NewReader(bufio.NewReader(wordlist)), nil
}

func ParseIssueDescription(g *Gobuster) {

	// Number of fields in the nikto test format
	const niktoFieldsNum = 13

	g.Opts.TestList = make(map[string]string)

	reader, err := g.getWordlist()
	if err != nil || reader == nil{
		return 
	}
	for{
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if len(record) < niktoFieldsNum{
			fmt.Fprintf(os.Stderr, "Wordlist is not nikto formatted")
			os.Exit(1)
		}
		g.Opts.TestList[record[0]] = record[10]
	}
}

// Start the busting of the website with the given
// set of settings from the command line.
func (g *Gobuster) Start() error {
	if err := g.plugin.Setup(g); err != nil {
		return err
	}

	var workerGroup sync.WaitGroup
	workerGroup.Add(g.Opts.Threads)

	wordChan := make(chan []string, g.Opts.Threads)

	ParseIssueDescription(g)

	// Create goroutines for each of the number of threads
	// specified.
	for i := 0; i < g.Opts.Threads; i++ {
		go g.worker(wordChan, &workerGroup)
	}

	reader, err := g.getWordlist()
	if err != nil {
		return err
	}

	if reader != nil{
Scan1:
		for {
			select {
			case <-g.context.Done():
				break Scan1
			default:
				if g.failsRatio > 50{
					break Scan1
				}
				record, err := reader.Read()
				if err == io.EOF {
					break Scan1
				}
				if err != nil {
					fmt.Println(err)
				}
				wordChan <- record
			}
		}
	}

	close(wordChan)
	workerGroup.Wait()
	close(g.resultChan)
	close(g.errorChan)
	return nil
}

// GetConfigString returns the current config as a printable string
func (g *Gobuster) GetConfigString() (string, error) {
	buf := &bytes.Buffer{}
	o := g.Opts
	if _, err := fmt.Fprintf(buf, "[+] Url/Domain   : %s\n", o.URL); err != nil {
		return "", err
	}
	if _, err := fmt.Fprintf(buf, "[+] Threads      : %d\n", o.Threads); err != nil {
		return "", err
	}

	wordlist := "stdin (pipe)"
	if o.Wordlist != "-" {
		wordlist = o.Wordlist
	}
	if _, err := fmt.Fprintf(buf, "[+] Wordlist     : %s\n", wordlist); err != nil {
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
}
