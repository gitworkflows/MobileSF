package gobusternikto

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"errors"
	"github.com/OJ/gobuster/libgobuster"
	"github.com/glaslos/ssdeep"
	"github.com/agext/levenshtein"

)

// GobusterDir is the main type to implement the interface
type GobusterNik struct{}

/*
	Setup gobuster 
	The function sends fake requests to the targets and stores 
	Wildcards:
		- the hashed request body and the request body content
*/
func (d GobusterNik) Setup(g *libgobuster.Gobuster) error {

	g.JsonResult = make(map[string]int)
	g.Interrupted = false
	g.IsReachable = true
	rand := libgobuster.RandomString(12,true,true)
	const reqN = 3
	var testUri [reqN]string
	var resDigest [reqN]string
	var resContent [reqN]string	
	var resLen [reqN]*int64
	testUri[0] = "g" + rand 							// /lowercasefilecheck
	testUri[1] = "G" + rand 							// /Folder/File/check
	testUri[2] = rand + "/" + rand + "/" + rand 	// /Uppercasefilecheck 


	//Check connection
	_, _, err := g.GetRequest(g.Opts.URL)
	libgobuster.Check(fmt.Sprintf("unable to connect to %s: ", g.Opts.URL), err)


	g.Opts.IsInit = true
	//Request unexisting pages
	for i := 0; i < reqN; i++ {
		_, resLen[i], _, resDigest[i], resContent[i], _ =  g.GetRequestNik(g.Opts.URL+testUri[i], g.Opts.Cookies, nil)
	}

	//Store Digests and results if the body of the response is present
	if resLen[0] != nil{
		for i := 0; i < reqN; i++ {
			g.Wildcards404[i] = resDigest[i]
			g.WildcardsContent404[i] = resContent[i]
		}
		g.Opts.EditHashTresh -= g.Opts.EditHashTreshI
	}else{
		for i := 0; i < reqN; i++ {
			g.Wildcards404[i] = ""
			g.WildcardsContent404[i] = ""
		}
	}
	g.Opts.IsInit = false

	return nil
}
/*
	This function substitute the Variables in the url with all the defined values 
	and returns the list of URIs
*/
func SubstituteString(g *libgobuster.Gobuster, uri string, vars []string, v int) []string {

	var uris = make([]string,65)
	var ret = make([]string,0)
	var idxUris = 0

	// Check if we are at the end of the recursion
	var stop = false
	if len(vars) == v+1{
		stop = true
	}

	sub, err := regexp.Compile(vars[v])
	libgobuster.Check("ERROR: Variable to compile result in bad regular expression",err)

	for j:= range g.Opts.Variables[vars[v]]{
		uris[idxUris] = sub.ReplaceAllLiteralString(uri,g.Opts.Variables[vars[v]][j])
		if !stop{
			temp := SubstituteString(g, uris[idxUris], vars, v+1)
			if temp == nil{
				return nil
			}
			ret = append(ret, temp...)
		}
		idxUris ++
	}

	if stop == true{
		return uris[0:idxUris]
	}else{
		return ret
	}
}

func ProcessUrl(g *libgobuster.Gobuster, uri string, word []string ) ([]libgobuster.Result, int, int){

	fails := 0
	success := 0
	url := g.BuildUrl(uri)

	dirResp, dirSize, positive, hash, content, error := g.GetRequestNik(url, g.Opts.Cookies, word)

	if error{
		fails = 1
	}else{
		success = 1
	}

	if dirResp != nil && positive {

		const scoreN = 3
		ssdeepScores := [scoreN]int{100,100,100}
		levenScores := [scoreN]float64{1.0,1.0,1.0}
		IsFuzzHash := (g.Wildcards404[0] != "")

		//Check for false positives

		if IsFuzzHash{
			// compute fuzzhash distances
			for i := 0; i < scoreN; i++ {
				ssdeepScores[i], _ = ssdeep.Distance(hash, g.Wildcards404[i])
				if ssdeepScores[i] >= g.Opts.HashTresh{
					positive = false
				}
			}
		}else{
			// compute edit distances
			for i := 0; i < scoreN; i++ {
				levenScores[i] = levenshtein.Match(hash, g.WildcardsContent404[i], nil)
				if levenScores[i] >= g.Opts.EditTresh{
					positive = false
				}
			}
		}

		if positive{
			return []libgobuster.Result{{
				Category:	word[0],
				Entity:		uri,
				Status:		*dirResp,
				Size:		dirSize,
				Hash: hash,
				Content: content,
			}}, fails, success
		}
	}
	return nil, fails, success

}
// Process is the process implementation of gobusterdir
func (d GobusterNik) Process(g *libgobuster.Gobuster, word []string) ([]libgobuster.Result, error, int, int) {

	fails := 0
	success := 0

	// Check for tuning tipes
	var tune = word[2]
	for l:=range tune{
		if strings.Contains(g.Opts.Tuning, tune[l:l+1]){
			break
		}
		return nil, errors.New("Tuning types substitution error"), 0,1
	}

	// Test-ID, Tuning Type, URI, HTTP Method, Match 1, Match 1 Or, Match1 And, Fail 1, Fail 2, Summary, HTTP Data, Headers
	var uri = word[3]
	var uris []string
	var max_variables = 3

	// Substitute variables and generate uri list
	if variables := g.Opts.VariableExp.FindAllString(uri,max_variables); variables != nil{
		uris = SubstituteString(g, uri, variables, 0)
		if uris == nil{
			return nil, errors.New("Variable substitution error"), 0,1
		}
	}else{
		uris = make([]string,1)
		uris[0] = uri
	}

	for i:=0; i< len(uris); i++ {

		// Try the DIR first
		if uris[i] == ""{
			continue
		}
		if ret, fail, succ :=ProcessUrl(g, uris[i], word); ret != nil{
			fails+=fail; success+=succ;
			return ret, nil, fails, success
		}else{
			fails+=fail; success+=succ;
		}
		
	}
	return nil,errors.New("NoResult"), fails, success
}

// ResultToString is the to string implementation of gobusterdir
func (d GobusterNik) ResultToString(g *libgobuster.Gobuster, r *libgobuster.Result) (*string, error) {

	g.JsonResult[fmt.Sprintf("%s--%d--%s--%s--%s", r.Entity, *r.Size, r.Category, r.Hash, r.Content)] = r.Status

	if g.Opts.Quiet{
		return nil,nil
	}

	buf := &bytes.Buffer{}

	// Prefix if we're in verbose mode
	if _, err := fmt.Fprintf(buf, "Found: "); err != nil {
		return nil, err
	}

	if g.Opts.Expanded {
		if _, err := fmt.Fprintf(buf, g.Opts.URL); err != nil {
			return nil, err
		}
	} else {
		if strings.HasPrefix(r.Entity, "/") != true{
			if _, err := fmt.Fprintf(buf, "/"); err != nil {
				return nil, err
			}
		}
	}
	if _, err := fmt.Fprintf(buf, r.Entity); err != nil {
		return nil, err
	}

	if !g.Opts.NoStatus {
		if _, err := fmt.Fprintf(buf, " (Status: %d)", r.Status); err != nil {
			return nil, err
		}
	}

	if r.Size != nil {
		if _, err := fmt.Fprintf(buf, " [Size: %d]", *r.Size); err != nil {
			return nil, err
		}
	}
	if _, err := fmt.Fprintf(buf, "\n"); err != nil {
		return nil, err
	}
	
	s := buf.String()
	return &s, nil
}
