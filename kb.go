// Add these imports to the existing list in kb.go
import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/google/uuid"
)

// Add these new structs for Confluence API interaction
type ConfluencePageRequest struct {
	Type  string                  `json:"type"`
	Title string                  `json:"title"`
	Space ConfluenceSpaceRequest  `json:"space"`
	Body  ConfluenceContentRequest `json:"body"`
}

type ConfluenceSpaceRequest struct {
	Key string `json:"key"`
}

type ConfluenceContentRequest struct {
	Storage ConfluenceStorageRequest `json:"storage"`
}

type ConfluenceStorageRequest struct {
	Value          string `json:"value"`
	Representation string `json:"representation"`
}

type ConfluencePageResponse struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

// Add this method to the DevSecOpsKB struct
func (kb *DevSecOpsKB) PublishToConfluence(config map[string]interface{}) error {
	if kb.FormatType != "confluence" {
		return fmt.Errorf("cannot publish to Confluence: KB format is not set to 'confluence'")
	}

	// Extract Confluence configuration
	confluenceConfig, ok := config["confluence"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid or missing Confluence configuration")
	}

	baseURL, _ := confluenceConfig["base_url"].(string)
	spaceKey, _ := confluenceConfig["space_key"].(string)
	username, _ := confluenceConfig["username"].(string)
	apiToken, _ := confluenceConfig["api_token"].(string)
	parentPageID, _ := confluenceConfig["parent_page_id"].(string)

	if baseURL == "" || spaceKey == "" || username == "" || apiToken == "" {
		return fmt.Errorf("missing required Confluence configuration parameters")
	}

	log.Printf("Starting Confluence KB publication to space %s", spaceKey)

	// Create parent page for the knowledge base if it doesn't exist
	kbPageID, err := kb.ensureKBParentPage(baseURL, spaceKey, username, apiToken, parentPageID)
	if err != nil {
		return fmt.Errorf("failed to create KB parent page: %v", err)
	}

	// Publish index page
	indexPageID, err := kb.publishIndexPage(baseURL, spaceKey, username, apiToken, kbPageID)
	if err != nil {
		return fmt.Errorf("failed to publish index page: %v", err)
	}
	log.Printf("Published KB index page with ID: %s", indexPageID)

	// Publish project pages
	for projectName, projectData := range kb.Metadata.Projects {
		projectPageID, err := kb.publishProjectPage(baseURL, spaceKey, username, apiToken, kbPageID, projectName, projectData)
		if err != nil {
			log.Printf("Warning: failed to publish project page for %s: %v", projectName, err)
			continue
		}
		log.Printf("Published project page for %s with ID: %s", projectName, projectPageID)

		// Publish alerts for this project
		for _, alertID := range projectData.Alerts {
			if alert, exists := kb.Metadata.Alerts[alertID]; exists {
				alertPageID, err := kb.publishAlertPage(baseURL, spaceKey, username, apiToken, projectPageID, alert)
				if err != nil {
					log.Printf("Warning: failed to publish alert page for %s: %v", alertID, err)
					continue
				}
				log.Printf("Published alert page for %s with ID: %s", alert.AlertName, alertPageID)
			}
		}
	}

	log.Printf("Knowledge base successfully published to Confluence")
	return nil
}

// Create a parent page for the knowledge base
func (kb *DevSecOpsKB) ensureKBParentPage(baseURL, spaceKey, username, apiToken, parentPageID string) (string, error) {
	title := "DevSecOps Knowledge Base"
	
	// Check if the page already exists
	if parentPageID != "" {
		// Verify the page exists
		url := fmt.Sprintf("%s/rest/api/content/%s", baseURL, parentPageID)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return "", err
		}
		
		req.Header.Set("Content-Type", "application/json")
		req.SetBasicAuth(username, apiToken)
		
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		
		if resp.StatusCode == http.StatusOK {
			return parentPageID, nil // Page exists, use it
		}
		// If we couldn't find the page, we'll create a new one
	}
	
	// Create new parent page
	url := fmt.Sprintf("%s/rest/api/content", baseURL)
	
	content := "<h1>DevSecOps Knowledge Base</h1><p>This is the parent page for the security knowledge base.</p>"
	pageRequest := ConfluencePageRequest{
		Type:  "page",
		Title: title,
		Space: ConfluenceSpaceRequest{
			Key: spaceKey,
		},
		Body: ConfluenceContentRequest{
			Storage: ConfluenceStorageRequest{
				Value:          content,
				Representation: "storage",
			},
		},
	}
	
	jsonData, err := json.Marshal(pageRequest)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, apiToken)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create KB parent page (status %d): %s", resp.StatusCode, string(bodyBytes))
	}
	
	var pageResponse ConfluencePageResponse
	err = json.NewDecoder(resp.Body).Decode(&pageResponse)
	if err != nil {
		return "", err
	}
	
	return pageResponse.ID, nil
}

// Publish the KB index page to Confluence
func (kb *DevSecOpsKB) publishIndexPage(baseURL, spaceKey, username, apiToken, parentPageID string) (string, error) {
	title := "Knowledge Base Index"
	
	// Read the index file content
	indexPath := filepath.Join(kb.KBDir, "index.html")
	content, err := os.ReadFile(indexPath)
	if err != nil {
		// If the index file doesn't exist, generate it first
		kb.generateIndex()
		content, err = os.ReadFile(indexPath)
		if err != nil {
			return "", err
		}
	}
	
	// Create the page with Confluence API
	url := fmt.Sprintf("%s/rest/api/content", baseURL)
	
	pageRequest := ConfluencePageRequest{
		Type:  "page",
		Title: title,
		Space: ConfluenceSpaceRequest{
			Key: spaceKey,
		},
		Body: ConfluenceContentRequest{
			Storage: ConfluenceStorageRequest{
				Value:          string(content),
				Representation: "storage",
			},
		},
	}
	
	// Add parent page relationship if provided
	if parentPageID != "" {
		// This is simplified; in production code you would need to add the ancestors array
		// For brevity, we're skipping that detail in this example
	}
	
	jsonData, err := json.Marshal(pageRequest)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, apiToken)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create index page (status %d): %s", resp.StatusCode, string(bodyBytes))
	}
	
	var pageResponse ConfluencePageResponse
	err = json.NewDecoder(resp.Body).Decode(&pageResponse)
	if err != nil {
		return "", err
	}
	
	return pageResponse.ID, nil
}

// Publish a project page to Confluence
func (kb *DevSecOpsKB) publishProjectPage(baseURL, spaceKey, username, apiToken, parentPageID, projectName string, projectData Project) (string, error) {
	// First, generate the project page if it doesn't exist
	projectFile := kb.generateProjectKBEntry(projectName)
	if projectFile == "" {
		return "", fmt.Errorf("failed to generate project page for %s", projectName)
	}
	
	content, err := os.ReadFile(projectFile)
	if err != nil {
		return "", err
	}
	
	// Create the page with Confluence API
	url := fmt.Sprintf("%s/rest/api/content", baseURL)
	
	pageRequest := ConfluencePageRequest{
		Type:  "page",
		Title: projectName,
		Space: ConfluenceSpaceRequest{
			Key: spaceKey,
		},
		Body: ConfluenceContentRequest{
			Storage: ConfluenceStorageRequest{
				Value:          string(content),
				Representation: "storage",
			},
		},
	}
	
	// Add parent page relationship if provided
	if parentPageID != "" {
		// Parent page relationship logic would go here
	}
	
	jsonData, err := json.Marshal(pageRequest)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, apiToken)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create project page (status %d): %s", resp.StatusCode, string(bodyBytes))
	}
	
	var pageResponse ConfluencePageResponse
	err = json.NewDecoder(resp.Body).Decode(&pageResponse)
	if err != nil {
		return "", err
	}
	
	return pageResponse.ID, nil
}

// Publish an alert page to Confluence
func (kb *DevSecOpsKB) publishAlertPage(baseURL, spaceKey, username, apiToken, parentPageID string, alert Alert) (string, error) {
	// Generate the alert page if it doesn't exist
	alertFile := kb.generateKBEntry(alert)
	if alertFile == "" {
		return "", fmt.Errorf("failed to generate alert page for %s", alert.AlertInstanceID)
	}
	
	content, err := os.ReadFile(alertFile)
	if err != nil {
		return "", err
	}
	
	title := fmt.Sprintf("%s - %s", alert.AlertName, alert.AlertInstanceID)
	
	// Create the page with Confluence API
	url := fmt.Sprintf("%s/rest/api/content", baseURL)
	
	pageRequest := ConfluencePageRequest{
		Type:  "page",
		Title: title,
		Space: ConfluenceSpaceRequest{
			Key: spaceKey,
		},
		Body: ConfluenceContentRequest{
			Storage: ConfluenceStorageRequest{
				Value:          string(content),
				Representation: "storage",
			},
		},
	}
	
	// Add parent page relationship if provided
	if parentPageID != "" {
		// Parent page relationship logic would go here
	}
	
	jsonData, err := json.Marshal(pageRequest)
	if err != nil {
		return "", err
	}
	
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(username, apiToken)
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create alert page (status %d): %s", resp.StatusCode, string(bodyBytes))
	}
	
	var pageResponse ConfluencePageResponse
	err = json.NewDecoder(resp.Body).Decode(&pageResponse)
	if err != nil {
		return "", err
	}
	
	return pageResponse.ID, nil
}

// Add these modifications to the main function
func main() {
	// Parse command line flags
	var (
		initialize    = flag.Bool("initialize", false, "Initialize the KB with canonical ZAP alerts")
		update        = flag.Bool("update", false, "Update the KB with new scan results")
		inputFile     = flag.String("input", "", "Input scan results file (required for update)")
		formatType    = flag.String("format", "obsidian", "Output format (obsidian or confluence)")
		outputDir     = flag.String("output", "devsecops_kb", "Output directory for the KB")
		projectName   = flag.String("project", "", "Project name (required for update)")
		publishToConf = flag.Bool("publish", false, "Publish KB to Confluence after initialization/update")
		configFile    = flag.String("config", "config.json", "Path to configuration file")
	)

	flag.Parse()

	// Validate flags
	if !*initialize && !*update {
		log.Fatal("Please specify either --initialize or --update")
	}

	if *update && (*inputFile == "" || *projectName == "") {
		log.Fatal("For --update, please provide --input and --project flags")
	}

	if *formatType != "obsidian" && *formatType != "confluence" {
		log.Fatal("Format must be either 'obsidian' or 'confluence'")
	}

	// Load config file if publishing to Confluence
	var config map[string]interface{}
	if *publishToConf {
		if _, err := os.Stat(*configFile); os.IsNotExist(err) {
			log.Fatalf("Configuration file %s not found!", *configFile)
		}
		
		configData, err := os.ReadFile(*configFile)
		if err != nil {
			log.Fatalf("Error reading configuration file: %v", err)
		}
		
		err = json.Unmarshal(configData, &config)
		if err != nil {
			log.Fatalf("Error parsing configuration file: %v", err)
		}
	}

	// Create or load the KB
	kb := NewDevSecOpsKB(*outputDir, *formatType)

	// Initialize or update the KB
	if *initialize {
		success := kb.initializeWithCanonicalAlerts()
		if !success {
			log.Fatal("KB initialization failed")
		}
	} else if *update {
		alertCount := kb.processZAPResults(*inputFile, *projectName)
		kb.generateIndex()
		log.Printf("KB update complete. Added %d new alerts for project '%s'.", alertCount, *projectName)
	}
	
	// Publish to Confluence if requested
	if *publishToConf {
		if *formatType != "confluence" {
			log.Fatal("Cannot publish to Confluence with format other than 'confluence'")
		}
		
		err := kb.PublishToConfluence(config)
		if err != nil {
			log.Fatalf("Failed to publish to Confluence: %v", err)
		}
	}

	log.Printf("KB is available at %s", *outputDir)
}
