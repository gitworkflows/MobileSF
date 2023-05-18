package libgobuster

import (
	"os"
	"strings"
	"encoding/json"
	"strconv"
	"fmt"
	"path"
	"github.com/glaslos/ssdeep"
	"github.com/agext/levenshtein"

)

type JsonOutputFinal struct {
	Error string `json:"_error,omitempty"`
	Body  map[string]map[int][][]string `json:"result,"`
}

func createDirectoryFuzzUrl(dir string, file string, rand string )([]string){

	var uris = make([]string,0)
	fileParts := strings.Split(dir, "/")
	idx := 0
	suffix :=""
	fuzzedUrl := ""

	if fileParts[idx] == ""{
		idx = 1
	}
	if file == ""{
		suffix = "/"
	}
	//left fuzz
	fileParts[idx] =  fileParts[idx] + rand
	fuzzedUrl =  path.Join(strings.Join(fileParts, "/"), file) + suffix
	uris = append(uris,fuzzedUrl)

	//right fuzz
	fileParts = strings.Split(dir, "/")
	fileParts[idx] =  rand + fileParts[idx]

	fuzzedUrl =  path.Join(strings.Join(fileParts, "/"), file) + suffix
	uris = append(uris,fuzzedUrl)

	return  uris
}

func createFileFuzzUrl(dir string, file string, rand string )([]string){
	var uris = make([]string,0)

	//fuzz filename
	fileParts := strings.Split(file, ".")
	//is hidden file
	ext, hidden, fileRight, fileLeft, extRight, extLeft, rest := "", "", "", "", "", "", ""
	baseIdx := 0 

	//If it's a hidden file fuzz from the name
	if fileParts[0] == ""{
		hidden = "."
		baseIdx += 1
	}

	fileRight = rand + fileParts[baseIdx]
	fileLeft = fileParts[baseIdx] + rand
	//If we have an extension fuzz
	if len(fileParts) > baseIdx + 1{
		baseIdx += 1
		for len(fileParts) > baseIdx + 1{
			rest = "." + fileParts[baseIdx]
			baseIdx += 1
		}
		extRight = "." + rand + fileParts[baseIdx]
		extLeft = "." + fileParts[baseIdx] + rand
		ext = "." + fileParts[baseIdx]
	}


	uris = append(uris, path.Join(dir,fmt.Sprintf("%s%s%s%s",hidden,fileRight,rest,ext)))
	uris = append(uris, path.Join(dir,fmt.Sprintf("%s%s%s%s",hidden,fileLeft,rest,ext)))
	if baseIdx != 0 && !(baseIdx == 1 && hidden == "."){
		uris = append(uris, path.Join(dir,fmt.Sprintf("%s%s%s%s",hidden,fileRight,rest,extRight)))
		uris = append(uris, path.Join(dir,fmt.Sprintf("%s%s%s%s",hidden,fileLeft,rest,extLeft)))
	}
	
	return uris
}

// Creates a list of fuzzed urls to be tested
func createFuzzUrls(url string) []string{
	dir, file := path.Split(url)
	rand := RandomString(12,true,true)
	var urls = make([]string,0)

	if (dir != "" && dir != "/") {
		urls = append(urls, createDirectoryFuzzUrl(dir,file,rand)...)
	}
	if (url == "/"){
		urls = append(urls, url + rand)
	}
	if file != "" {
		//fuzz filename
		urls = append(urls,createFileFuzzUrl(dir,file,rand)...)
	}
	return urls
}

// Check if two results entries are similar
func isSimilar(oldHash, newHash, oldCont, newCont, uri string, contentLen int, g *Gobuster,hashtresh int, editresh float64) bool{

	var ssDistance int = 0
	var levDistance float64 = 0.0
	var filter = false

	if (oldHash != "" && newHash == "") || (oldHash == "" && newHash != ""){
		filter = false
	}
	if (oldHash != "" && newHash != ""){
		ssDistance, _ = ssdeep.Distance(newHash, oldHash)
		if (ssDistance > hashtresh){
			filter = true
		}		
	}
	if (oldHash == "" && newHash == ""){
		levDistance = levenshtein.Match(newCont, oldCont, nil)
		if (levDistance > editresh){
			filter = true
		}
	}

	if (filter) {
		//Similar
		return true
	}
	//Not similar
	return false
}

// For each entry in the results check if similar results were found.
// Remove them if more than a defined treshold 
func filterSimilarResults(g *Gobuster){
	
	var similarityTreshold = 2
	for resultEntry, _ := range g.JsonResult {

		entryParts := strings.Split(resultEntry, "--")
		oldHash := entryParts[3]
		oldCont := entryParts[4]
		oldLen, _ := strconv.Atoi(entryParts[1])
		
		if g.Opts.Verbose {
			fmt.Printf("[i] Filtering similar responses for %s\n",
						string(entryParts[0]))
		}
		
		//Check for similar results
		similar := make([]string, 0)
		for target, _ := range g.JsonResult {
			targetParts := strings.Split(target, "--")
			newHash := targetParts[3]
			newCont := targetParts[4]
			uri := targetParts[0]
			
			if isSimilar(oldHash, newHash, oldCont, newCont, uri, oldLen, g, g.Opts.HashTresh,g.Opts.EditTresh){
				similar = append(similar,target)
			}
		}
		// Delete similar results from results
		if len(similar) > similarityTreshold {
			for i := 0; i < len(similar); i++ {
				delete(g.JsonResult, similar[i])
			}
		}		
	}
}
func SendRequestAndTest(target, oldHash, oldCont string, oldLen int, word []string, hashtresh int, editresh float64, uri string, g *Gobuster)(bool){

	url := g.BuildUrl(target)
	_, size, _, newHash, newCont, _  := g.GetRequestNik(url, "", word)

	if size != nil && isSimilar(oldHash, newHash, oldCont, newCont, uri, oldLen, g, hashtresh, editresh){
		return true
	}
	return false
}

func fuzzUrl(resultEntry string, statusCode int, g *Gobuster) bool{

	var parts = strings.Split(resultEntry, "--")
	var oldHash = parts[3]
	var oldCont = parts[4]
	var oldLen, _ = strconv.Atoi(parts[1])
	var uri =  string(parts[0])
	var word = []string{"", "", "", "", "GET", strconv.Itoa(statusCode),
						 "", "", "", "", "", "", ""}

	if g.Opts.Verbose {
		fmt.Fprintf(os.Stdout,"[!] Check if uri produce same result for %s\n",uri)
	}

	// Check if the same request produce the same response
	for i:=0; i<2; i++{
		if !SendRequestAndTest(string(parts[0]), oldHash, oldCont, oldLen, word, 90, 0.1, uri, g){
			return true
		}
	}

	if g.Opts.Verbose {
		fmt.Fprintf(os.Stdout,"[!] Fuzzing uri of %s\n",uri)
	}

	urls := createFuzzUrls(string(parts[0]))
	// Test the set of fuzzed uri
	for i:=range urls{
		if urls[i] == ""{
			continue
		}
		if SendRequestAndTest(urls[i], oldHash, oldCont, oldLen, word, g.Opts.HashTresh, g.Opts.EditTresh, uri, g){
			return true
		}
	}
	return false

}

// Map the true positives in the right output format
// Additionally add another layer of filtering in case of partial results
func mapResult(resultMap map[string]map[int][][]string, g *Gobuster) JsonOutputFinal{

	result := JsonOutputFinal{Body: resultMap}

	if !g.IsReachable {
		result.Error = "unreachable host"
		return result
	}

	if g.Interrupted {
		result.Error = "partial result" 
		return result
	}
	return result
}

// Removes the false positives to the results in several steps
func RemoveFalsePositives(g *Gobuster) []byte{

	const filterMinimumLen = 3
	var specialCode = 999
	var resultMap = make(map[string]map[int][][]string)

	if g.Opts.Verbose {
		fmt.Println("<------ Remove false positives ------>")
		fmt.Printf("[i] Results before filtering: ")
		fmt.Println(g.JsonResult)
	}

	if g == nil{
		if !g.Opts.Quiet{
			fmt.Println("[!] False positives filtering failed: the gobuster object is not inizialized")
		}
		out, _ := json.Marshal(JsonOutputFinal{Body: resultMap})
		return out
	}

	if g.Opts.Verbose{
		fmt.Println("[i] FP Stage one - Filter similar results")
	}
	// Filtering part 1: filter similar results
	if len(g.JsonResult) >= filterMinimumLen{
		filterSimilarResults(g)
	}

	if g.Opts.Verbose{
		fmt.Println("[i] FP Stage two - Fuzz filtering")
	}

	for resultEntry, statusCode := range g.JsonResult {
		parts := strings.Split(resultEntry, "--")
		category := parts[2]
		contentLen, _ := strconv.Atoi(parts[1])

		// Filtering part 2: fuzz positive results uri
		if fuzzUrl(resultEntry, statusCode, g){
			if g.Opts.Verbose {
				fmt.Fprintf(os.Stderr,"[i] ... Filtering out %s\n",string(parts[0]))
			}
			continue
		}

		if resultMap[category] == nil {
			resultMap[category] = make(map[int][][]string)
		}

		// Filter out 0 len reponses		
		if  contentLen == 0 {
			statusCode = specialCode
		}
		resultMap[category][statusCode] = append(resultMap[category][statusCode], append(parts[0:2],parts[4]))
	}
	// Map the final results
	result := mapResult(resultMap, g)

	// Create json object
	out, _ := json.Marshal(result)
	return out	
}