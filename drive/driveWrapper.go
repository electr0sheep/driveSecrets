/*
Copyright © 2019 electr0sheep <electr0sheep@electr0sheep.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package driveWrapper

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"main/crypto"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
)

func RemoveKeyFromFile(key string, verbose bool) string {
	credentials := getCredentials("credentials.json")

	config := getConfig(credentials)

	client := getClient(config)

	service := getDriveService(client)

	file := getOrCreateDocByNameSearchString("hi.txt", service, verbose)

	contents := readFileContents(file, service)

	decrypted_body := crypto.Decrypt(contents)

	unmarshalledJSON := getUnmarshalledJSON(decrypted_body)

	if unmarshalledJSON[key] == nil {
		return fmt.Sprintf("Key '%s' does not exist!", key)
	} else {
		delete(unmarshalledJSON, key)
	}

	marshalledJSON := getMarshalledJSON(unmarshalledJSON)

	saveFile(file, service, string(marshalledJSON))

	return prettyPrintJSON(string(marshalledJSON))
}

func AddKeyValueToFile(key string, value string, verbose bool) string {
	credentials := getCredentials("credentials.json")

	config := getConfig(credentials)

	client := getClient(config)

	service := getDriveService(client)

	file := getOrCreateDocByNameSearchString("hi.txt", service, verbose)

	contents := readFileContents(file, service)

	decrypted_body := crypto.Decrypt(contents)

	unmarshalledJSON := getUnmarshalledJSON(decrypted_body)

	if unmarshalledJSON[key] != nil {
		return fmt.Sprintf("Key '%s' already exists!", key)
	} else {
		unmarshalledJSON[key] = value
	}

	marshalledJSON := getMarshalledJSON(unmarshalledJSON)

	saveFile(file, service, string(marshalledJSON))

	return prettyPrintJSON(string(marshalledJSON))
}

func ReadFile(verbose bool) string {
	credentials := getCredentials("credentials.json")

	config := getConfig(credentials)

	client := getClient(config)

	service := getDriveService(client)

	file := getOrCreateDocByNameSearchString("hi.txt", service, verbose)

	contents := readFileContents(file, service)

	decrypted_body := crypto.Decrypt(contents)

	return prettyPrintJSON(decrypted_body)
}

func getMarshalledJSON(unmarshalledJSON map[string]interface{}) []byte {
	marshalledJSON, err := json.Marshal(unmarshalledJSON)
	if err != nil {
		log.Fatalf("Unable to marshall JSON: %v", err)
	}

	return marshalledJSON
}

func saveFile(file *drive.File, srv *drive.Service, contents string) {
	file, err := srv.Files.Update(file.Id, &drive.File{Name: file.Name}).Media(strings.NewReader(crypto.Encrypt(contents))).Do()
	if err != nil {
		log.Fatalf("Unable to save file: %v", err)
	}
}

func getCredentials(filename string) []byte {
	credentials, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	return credentials
}

func getConfig(credentials []byte) *oauth2.Config {
	// If modifying these scopes, delete your previously saved token.json.
	config, err := google.ConfigFromJSON(credentials, drive.DriveScope)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}
	return config
}

func prettyPrintJSON(JSON string) string {
	var prettyJSON bytes.Buffer

	err := json.Indent(&prettyJSON, bytes.Trim([]byte(JSON), "\x00"), "", "  ")
	if err != nil {
		log.Fatalf("Unable to pretty-print JSON: %v", err)
	}

	return prettyJSON.String()
}

func getUnmarshalledJSON(content string) map[string]interface{} {
	var unmarshalledJSON map[string]interface{}

	err := json.Unmarshal(bytes.Trim([]byte(content), "\x00"), &unmarshalledJSON)
	if err != nil {
		log.Fatalf("%v", err)
	}

	return unmarshalledJSON
}

func getDriveService(client *http.Client) *drive.Service {
	srv, err := drive.New(client)
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}

	return srv
}

func readFileContents(file *drive.File, srv *drive.Service) string {
	response, _ := srv.Files.Get(file.Id).Download()
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	return string(body)
}

func getOrCreateDocByNameSearchString(name string, srv *drive.Service, verbose bool) *drive.File {
	fileListResult, err := srv.Files.List().Q(fmt.Sprintf("name = '%s'", name)).Do()
	if err != nil {
		log.Fatalf("Unable to list files: %v", err)
	}

	var file *drive.File = nil

	if len(fileListResult.Files) > 0 {
		if verbose {
			fmt.Printf("File already exists\n")
		}
		file = fileListResult.Files[0]
	} else {
		if verbose {
			fmt.Printf("File did not already exist, creating\n")
		}
		file, err = srv.Files.Create(&drive.File{Name: name}).Do()
		if err != nil {
			log.Fatalf("Unable to create file: %v", err)
		}
	}

	return file
}

// Retrieve a token, saves the token, then returns the generated client.
func getClient(config *oauth2.Config) *http.Client {
	// The file token.json stores the user's access and refresh tokens, and is
	// created automatically when the authorization flow completes for the first
	// time.
	tokFile := "token.json"
	tok, err := tokenFromFile(tokFile)
	if err != nil {
		tok = getTokenFromWeb(config)
		saveToken(tokFile, tok)
	}
	return config.Client(context.Background(), tok)
}

// Request a token from the web, then returns the retrieved token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var authCode string
	if _, err := fmt.Scan(&authCode); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

// Retrieves a token from a local file.
func tokenFromFile(file string) (*oauth2.Token, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tok := &oauth2.Token{}
	err = json.NewDecoder(f).Decode(tok)
	return tok, err
}

// Saves a token to a file path.
func saveToken(path string, token *oauth2.Token) {
	fmt.Printf("Saving credential file to: %s\n", path)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Unable to cache oauth token: %v", err)
	}
	defer f.Close()
	json.NewEncoder(f).Encode(token)
}
