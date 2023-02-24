package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

func main() {

	red := "\033[31m"
	reset := "\033[0m"
	banner := red + `
	
	
██▒   █▓▄▄▄█████▓ ▒█████  ▄▄▄█████▓ ▄▄▄       ██▓    ▓█████  ███▄    █  █    ██  ███▄ ▄███▓
▓██░   █▒▓  ██▒ ▓▒▒██▒  ██▒▓  ██▒ ▓▒▒████▄    ▓██▒    ▓█   ▀  ██ ▀█   █  ██  ▓██▒▓██▒▀█▀ ██▒
 ▓██  █▒░▒ ▓██░ ▒░▒██░  ██▒▒ ▓██░ ▒░▒██  ▀█▄  ▒██░    ▒███   ▓██  ▀█ ██▒▓██  ▒██░▓██    ▓██░
  ▒██ █░░░ ▓██▓ ░ ▒██   ██░░ ▓██▓ ░ ░██▄▄▄▄██ ▒██░    ▒▓█  ▄ ▓██▒  ▐▌██▒▓▓█  ░██░▒██    ▒██ 
   ▒▀█░    ▒██▒ ░ ░ ████▓▒░  ▒██▒ ░  ▓█   ▓██▒░██████▒░▒████▒▒██░   ▓██░▒▒█████▓ ▒██▒   ░██▒
   ░ ▐░    ▒ ░░   ░ ▒░▒░▒░   ▒ ░░    ▒▒   ▓▒█░░ ▒░▓  ░░░ ▒░ ░░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░   ░  ░
   ░ ░░      ░      ░ ▒ ▒░     ░      ▒   ▒▒ ░░ ░ ▒  ░ ░ ░  ░░ ░░   ░ ▒░░░▒░ ░ ░ ░  ░      ░
     ░░    ░      ░ ░ ░ ▒    ░        ░   ▒     ░ ░      ░      ░   ░ ░  ░░░ ░ ░ ░      ░   
      ░               ░ ░                 ░  ░    ░  ░   ░  ░         ░    ░            ░   
     ░                                                                                       
     		subdomain enumeration via virustotal	@zyad-Elsayed		` + reset
     
     
	fmt.Println(banner)

	// Get the path to the input file from the command line argument
	if len(os.Args) < 2 {
		fmt.Println("Please provide the path to the input file as an argument")
		return
	}
	inputPath := os.Args[1]

	// Read the input file
	inputFile, err := os.Open(inputPath)
	if err != nil {
		fmt.Println("Error opening input file:", err)
		return
	}
	defer inputFile.Close()

	// Create the output file
	outputFilename := fmt.Sprintf("virustotal_%s.txt", filepath.Base(inputPath))
	outputFile, err := os.Create(outputFilename)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer outputFile.Close()

	// Loop through each domain in the input file
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		domain := scanner.Text()
		fmt.Println("Enumerating subdomains for", domain)

		url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s/relationships/subdomains?limit=1000", domain)

		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			fmt.Println("Error creating request:", err)
			continue
		}

		req.Header.Add("accept", "application/json")
		req.Header.Add("x-apikey", "xxxxx")

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println("Error sending request:", err)
			continue
		}
		defer res.Body.Close()

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			fmt.Println("Error reading response body:", err)
			continue
		}

		// Unmarshal the response body into a JSON object
		var response map[string]interface{}
		err = json.Unmarshal(body, &response)
		if err != nil {
			fmt.Println("Error unmarshaling response body:", err)
			continue
		}

		// Extract the subdomains from the response
		var subdomains []string
		data, ok := response["data"].([]interface{})
		if !ok {
			fmt.Println("Error extracting subdomains:", err)
			continue
		}

		for _, d := range data {
			subdomain := d.(map[string]interface{})["id"].(string)
			subdomain = strings.ToLower(subdomain)
			match, err := regexp.MatchString(`^\*?\w+\.`+domain+`$`, subdomain)
			if err != nil {
				fmt.Println("Error matching subdomain:", err)
				continue
			}
			if match {
				subdomains = append(subdomains, subdomain)
			}
		}

		// Write the subdomains to the output file
		for _, subdomain := range subdomains {
			_, err = outputFile.WriteString(subdomain + "\n")
			if err != nil {
				fmt.Println("Error writing to output file:", err)
				continue
			}
		}

		fmt.Printf("%d subdomains matching *.%s written to %s\n", len(subdomains), domain, outputFilename)
	}
}
