package main

//----------------------------------------------------
// Gobuster -- by OJ Reeves
//
// A crap attempt at building something that resembles
// dirbuster or dirb using Go. The goal was to build
// a tool that would help learn Go and to actually do
// something useful. The idea of having this compile
// to native code is also appealing.
//
// Run: gobuster -h
//
// Please see THANKS file for contributors.
// Please see LICENSE file for license details.
//
//----------------------------------------------------

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"regexp"
	"encoding/json"
	"github.com/glaslos/ssdeep"
	"gobusternikto"
	"github.com/OJ/gobuster/libgobuster"
	"golang.org/x/crypto/ssh/terminal"
)

func ruler() {
	fmt.Println("=====================================================")
}
func ruler2() {
	fmt.Println("-----------------------------------------------------")
}
func banner() {
	fmt.Printf("Gobuster v.srlabs.%s (OJ Reeves @TheColonial)\nModified in SRLabs by Emanuele Vineti\n", libgobuster.VERSION)
}

func resultWorker(g *libgobuster.Gobuster, filename string, wg *sync.WaitGroup) {
	defer wg.Done()
	var f *os.File
	var err error
	if filename != "" {
		f, err = os.Create(filename)
		libgobuster.Check("Error creating output file: ",err)
	}
	for r := range g.Results() {
		s, err := r.ToString(g)
		libgobuster.Check("",err)
		if s != "" {
			g.ClearProgress()
			s = strings.TrimSpace(s)
			fmt.Println(s)
			if f != nil {
				err = writeToFile(f, s)
				libgobuster.Check("Error writing to output file:",err)
			}
		}
	}
}

func errorWorker(g *libgobuster.Gobuster, wg *sync.WaitGroup) {
	defer wg.Done()
	for e := range g.Errors() {
		if !g.Opts.Quiet {
			g.ClearProgress()
			log.Printf("[!] %v", e)
		}
	}
}

func progressWorker(c context.Context, g *libgobuster.Gobuster) {
	tick := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-tick.C:
			g.PrintProgress()
		case <-c.Done():
			return
		}
	}
}

func writeToFile(f *os.File, output string) error {
	_, err := f.WriteString(fmt.Sprintf("%s\n", output))
	libgobuster.Check("Error writing to file: ",err)
	return nil
}

type JsonOutputFinal struct {
	Error string `json:"_error,omitempty"`
	Body  map[string]map[int][][]string `json:"result,"`
}

func TrimSpaceNewlineInString(s string) string{
	re := regexp.MustCompile("[ \n\r]+")
	return re.ReplaceAllString(s, " ")
}

func PrintResult(out []byte,g *libgobuster.Gobuster){
	var result JsonOutputFinal
	json.Unmarshal(out, &result)
	fmt.Println("")
	resultmap := result.Body
	ruler()
	log.Println(" Results ")
	ruler()
	for category := range resultmap{
		ruler2()
		fmt.Fprintf(os.Stdout, "- Test Code: %s\n", category)
		if val, ok := g.Opts.TestList[category]; ok{
			fmt.Fprintf(os.Stdout, "- Description: %s\n", val)
		}
		ruler2()
		fmt.Println("")
		for status := range resultmap[category]{
			for i := range resultmap[category][status]{
				fmt.Fprintf(os.Stdout,"[*] uri: \"%s\", status: \"%d\" len: %s, body: \"%s\"\n",resultmap[category][status][i][0],
						status, resultmap[category][status][i][1],TrimSpaceNewlineInString(resultmap[category][status][i][2]))
			}
		}
		fmt.Println("")

	}
}
func PrintResultQuiet(out []byte,g *libgobuster.Gobuster){
	var result JsonOutputFinal
	json.Unmarshal(out, &result)
	resultmap := result.Body
	for category := range resultmap{
		for status := range resultmap[category]{
			for i := range resultmap[category][status]{
				fmt.Println(g.BuildUrl(resultmap[category][status][i][0]))
			}
		}
	}
}
func OutJsonOnFile(out []byte, path string){
	file, err := os.Create(path)
	libgobuster.Check("Error creating json output file: ", err)
	defer file.Close()
	_, err = file.Write(out)
	libgobuster.Check("Error writing to json output file", err)
}


func main() {
	var outputFilename string
	o := libgobuster.NewOptions()
	flag.IntVar(&o.Threads, "t", 10, "Number of concurrent threads")
	flag.StringVar(&o.Wordlist, "w", "", "Path to the wordlist")
	flag.StringVar(&outputFilename, "o", "", "Output file to write results to (defaults to stdout)")
	flag.StringVar(&o.URL, "u", "", "The target URL or Domain")
	flag.StringVar(&o.JsonOut, "oj", "", "The output file for the result in JSON format")
	flag.StringVar(&o.Cookies, "c", "", "Cookies to use for the requests (dir mode only)")
	flag.StringVar(&o.Username, "U", "", "Username for Basic Auth (dir mode only)")
	flag.StringVar(&o.Password, "P", "", "Password for Basic Auth (dir mode only)")
	flag.StringVar(&o.UserAgent, "a", "", "Set the User-Agent string (dir mode only)")
	flag.StringVar(&o.Proxy, "p", "", "Proxy to use for requests [http(s)://host:port] (dir mode only)")
	flag.DurationVar(&o.Timeout, "to", 10*time.Second, "HTTP Timeout in seconds (dir mode only)")
	flag.BoolVar(&o.Verbose, "v", false, "Verbose output (errors)")
	flag.BoolVar(&o.FollowRedirect, "r", false, "Follow redirects")
	flag.BoolVar(&o.Quiet, "q", false, "Don't print the banner and other noise")
	flag.BoolVar(&o.Expanded, "e", false, "Expanded mode, print full URLs")
	flag.BoolVar(&o.NoStatus, "n", false, "Don't print status codes")
	flag.BoolVar(&o.IncludeLength, "l", false, "Include the length of the body in the output (dir mode only)")
	flag.BoolVar(&o.WildcardForced, "fw", false, "Force continued operation when wildcard found")
	flag.BoolVar(&o.InsecureSSL, "k", false, "Skip SSL certificate verification")
	flag.BoolVar(&o.NoProgress, "np", false, "Don't display progress")
	flag.StringVar(&o.Tuning, "T", "0:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:g", "Specify tests categoriesto run")
	flag.StringVar(&o.VariablesPath, "V", "", "Nikto db variables file")

	flag.Parse()

	// Disable min length in ssdeep
	ssdeep.Force = true
	o.HashTresh = 68
	o.EditTresh	= 0.3 //TOEDIT
	o.EditHashTresh = 200
	o.EditHashTreshI = 100

	// Prompt for PW if not provided
	if o.Username != "" && o.Password == "" {
		fmt.Printf("[?] Auth Password: ")
		passBytes, err := terminal.ReadPassword(int(syscall.Stdin))
		// print a newline to simulate the newline that was entered
		// this means that formatting/printing after doesn't look bad.
		fmt.Println("")
		libgobuster.Check("Auth username given but reading of password failed: ", err)
		o.Password = string(passBytes)
	}
	// Setup the closing function
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Select Gobuster plugin
	var plugin libgobuster.GobusterPlugin

	plugin = gobusternikto.GobusterNik{}

	// Create new Gobuster object
	gobuster, err := libgobuster.NewGobuster(ctx, o, plugin)
	libgobuster.Check("", err)


	// Introduction output message
	if !o.Quiet {
		fmt.Println("")
		ruler()
		banner()
		ruler()
		c, err := gobuster.GetConfigString()
		libgobuster.Check("Error on creating config string: ", err)
		fmt.Println(c)
		ruler()
		log.Println(" Starting gobuster")
		ruler()
	}

	// catch and handle with interrupt signals
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		for range signalChan {
			// caught CTRL+C
			if !gobuster.Opts.Quiet {
				fmt.Println("\n[!] Keyboard interrupt detected, terminating...")
				gobuster.Interrupted = true
			}
			cancel()
		}
	}()

	// Run Workers
	var wg sync.WaitGroup
	wg.Add(2)
	go errorWorker(gobuster, &wg)
	go resultWorker(gobuster, outputFilename, &wg)

	if !o.Quiet && !o.NoProgress {
		go progressWorker(ctx, gobuster)
	}
	err = gobuster.Start()
	libgobuster.Check("Error during gobuster: ",err)
	
	// Remove false positives and print the json output
	time.Sleep(3 * time.Second)
	if gobuster.Interrupted{
		gobuster.Interrupted = false
		ctx, cancel = context.WithCancel(context.Background())
		gobuster.NewContext(ctx)
		h, _ :=libgobuster.NewHTTPClient(ctx, gobuster.Opts)
		gobuster.NewHttp(h)
	}
	out := libgobuster.RemoveFalsePositives(gobuster)
	// Print results
	if !o.Quiet{
		PrintResult(out, gobuster)
	}else{
		PrintResultQuiet(out, gobuster)
	}
	if o.JsonOut != ""{
		OutJsonOnFile(out,o.JsonOut)
	}
	// call cancel func to free ressources and stop progressFunc
	cancel()
	// wait for all output funcs to finish
	wg.Wait()
	
	if !o.Quiet {
		gobuster.ClearProgress()
		ruler()
		log.Println("Finished")
		ruler()
	}
}
