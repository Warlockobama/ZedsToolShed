package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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

// Constants
const (
	KB_META_FILE         = "kb_metadata.json"
	CANONICAL_VULNS_FILE = "canonical_vulns.json"
	TEMPLATES_DIR        = "templates"
)

// Structs for ZAP data
type ZAPInstance struct {
	URI      string `json:"uri"`
	Evidence string `json:"evidence"`
}

type ZAPAlert struct {
	PluginID    string        `json:"pluginId"`
	Name        string        `json:"name"`
	RiskDesc    string        `json:"riskdesc"`
	CWEID       string        `json:"cweid"`
	Description string        `json:"desc"`
	Solution    string        `json:"solution"`
	Reference   string        `json:"reference"`
	Instances   []ZAPInstance `json:"instances"`
}

type ZAPSite struct {
	Alerts []ZAPAlert `json:"alerts"`
}

type ZAPReport struct {
	Site []ZAPSite `json:"site"`
}

// Structs for vulnerability data
type Vulnerability struct {
	AlertID     string            `json:"alert_id"`
	AlertName   string            `json:"alert_name"`
	AlertType   string            `json:"alert_type"`
	Status      string            `json:"status"`
	Risk        string            `json:"risk"`
	CWEID       string            `json:"cweid"`
	Description string            `json:"description"`
	Remediation string            `json:"remediation"`
	Reference   string            `json:"reference"`
	SourceURL   string            `json:"source_url"`
	GitSrc      []string          `json:"gitsrc"`
	CanonicalID string            `json:"canonical_id"`
	CWEDetails  map[string]string `json:"cwe_details,omitempty"`
}

type CanonicalVulns struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Alert represents an alert instance in the KB
type Alert struct {
	AlertInstanceID  string                   `json:"alert_instance_id"`
	AlertID          string                   `json:"alert_id"`
	AlertName        string                   `json:"alert_name"`
	AlertType        string                   `json:"alert_type"`
	Risk             string                   `json:"risk"`
	CWEID            string                   `json:"cweid"`
	CWEDetails       map[string]string        `json:"cwe_details,omitempty"`
	Description      string                   `json:"description"`
	Remediation      string                   `json:"remediation"`
	TechnicalDetails string                   `json:"technical_details"`
	AffectedURLs     []string                 `json:"affected_urls"`
	References       string                   `json:"references"`
	Status           string                   `json:"status"`
	TriageStatus     string                   `json:"triage_status"`
	Project          string                   `json:"project"`
	AssignedTo       string                   `json:"assigned_to"`
	DateAdded        string                   `json:"date_added"`
	DateUpdated      string                   `json:"date_updated"`
	History          []map[string]interface{} `json:"history"`
	AnalysisNotes    string                   `json:"analysis_notes"`
}

// Scan represents a security scan record
type Scan struct {
	ScanID     string `json:"scan_id"`
	ScanDate   string `json:"scan_date"`
	AlertCount int    `json:"alert_count"`
}

// Project represents a project in the KB
type Project struct {
	ProjectID   string   `json:"project_id"`
	DateAdded   string   `json:"date_added"`
	DateUpdated string   `json:"date_updated"`
	Owner       string   `json:"owner"`
	Alerts      []string `json:"alerts"`
	Scans       []Scan   `json:"scans"`
}

// Stats represents KB statistics
type Stats struct {
	TotalAlerts          int `json:"total_alerts"`
	TriagedAlerts        int `json:"triaged_alerts"`
	FalsePositives       int `json:"false_positives"`
	AcceptedRisks        int `json:"accepted_risks"`
	FixedVulnerabilities int `json:"fixed_vulnerabilities"`
}

// KBMetadata represents the KB metadata
type KBMetadata struct {
	CreatedDate     string             `json:"created_date"`
	LastUpdated     string             `json:"last_updated"`
	Projects        map[string]Project `json:"projects"`
	Alerts          map[string]Alert   `json:"alerts"`
	CanonicalAlerts map[string]string  `json:"canonical_alerts"`
	Stats           Stats              `json:"stats"`
}

// DevSecOpsKB represents the main KB structure
type DevSecOpsKB struct {
	KBDir          string
	FormatType     string
	CanonicalVulns map[string]Vulnerability
	Metadata       KBMetadata
	MetadataPath   string
}

// NewDevSecOpsKB creates a new KB instance
func NewDevSecOpsKB(kbDir string, formatType string) *DevSecOpsKB {
	kb := &DevSecOpsKB{
		KBDir:          kbDir,
		FormatType:     formatType,
		CanonicalVulns: make(map[string]Vulnerability),
		MetadataPath:   filepath.Join(kbDir, KB_META_FILE),
	}

	// Create KB directory structure
	os.MkdirAll(kbDir, 0755)
	os.MkdirAll(filepath.Join(kbDir, "alerts"), 0755)
	os.MkdirAll(filepath.Join(kbDir, "projects"), 0755)
	os.MkdirAll(filepath.Join(kbDir, "templates"), 0755)

	// Load metadata if it exists
	if _, err := os.Stat(kb.MetadataPath); err == nil {
		metadataFile, err := os.ReadFile(kb.MetadataPath)
		if err == nil {
			err = json.Unmarshal(metadataFile, &kb.Metadata)
			if err != nil {
				log.Printf("Error unmarshaling metadata: %v", err)
				kb.initializeMetadata()
			}
		} else {
			log.Printf("Error reading metadata file: %v", err)
			kb.initializeMetadata()
		}
	} else {
		kb.initializeMetadata()
	}

	// Create template files if they don't exist
	kb.ensureTemplates()

	// Load canonical vulnerabilities
	canonicalVulnsPath := filepath.Join(kbDir, CANONICAL_VULNS_FILE)
	if _, err := os.Stat(canonicalVulnsPath); err == nil {
		vulnsFile, err := os.ReadFile(canonicalVulnsPath)
		if err == nil {
			var vulnsData CanonicalVulns
			err = json.Unmarshal(vulnsFile, &vulnsData)
			if err == nil {
				for _, vuln := range vulnsData.Vulnerabilities {
					if vuln.AlertID != "" {
						kb.CanonicalVulns[vuln.AlertID] = vuln
					}
				}
			} else {
				log.Printf("Error unmarshaling canonical vulnerabilities: %v", err)
			}
		} else {
			log.Printf("Error reading canonical vulnerabilities file: %v", err)
		}
	} else {
		log.Printf("%s not found. Run with --initialize flag to generate canonical vulnerabilities.", CANONICAL_VULNS_FILE)
	}

	return kb
}

// Initialize metadata with default values
func (kb *DevSecOpsKB) initializeMetadata() {
	now := time.Now().Format(time.RFC3339)
	kb.Metadata = KBMetadata{
		CreatedDate:     now,
		LastUpdated:     now,
		Projects:        make(map[string]Project),
		Alerts:          make(map[string]Alert),
		CanonicalAlerts: make(map[string]string),
		Stats: Stats{
			TotalAlerts:          0,
			TriagedAlerts:        0,
			FalsePositives:       0,
			AcceptedRisks:        0,
			FixedVulnerabilities: 0,
		},
	}
	kb.saveMetadata()
}

// Save metadata to file
func (kb *DevSecOpsKB) saveMetadata() {
	kb.Metadata.LastUpdated = time.Now().Format(time.RFC3339)
	metadataJSON, err := json.MarshalIndent(kb.Metadata, "", "  ")
	if err != nil {
		log.Printf("Error marshaling metadata: %v", err)
		return
	}

	err = os.WriteFile(kb.MetadataPath, metadataJSON, 0644)
	if err != nil {
		log.Printf("Error writing metadata file: %v", err)
	}
}

// Ensure that template files exist
func (kb *DevSecOpsKB) ensureTemplates() {
	templates := map[string]string{
		"alert_obsidian.md": `---
alert_id: {{.AlertID}}
alert_name: {{.AlertName}}
risk: {{.Risk}}
cwe: {{.CWEID}}
date_added: {{.DateAdded}}
date_updated: {{.DateUpdated}}
status: {{.Status}}
triage_status: {{.TriageStatus}}
project: {{.Project}}
assigned_to: {{.AssignedTo}}
---

# {{.AlertName}}

## Alert Details
- **Risk Level**: {{.Risk}}
- **CWE**: [{{.CWEID}}](https://cwe.mitre.org/data/definitions/{{.CWEID}}.html)
- **Status**: {{.Status}}
- **Triage Status**: {{.TriageStatus}}
- **Project**: [[{{.Project}}]]
- **Assigned To**: {{.AssignedTo}}
- **Date Added**: {{.DateAdded}}
- **Last Updated**: {{.DateUpdated}}

## Description
{{.Description}}

## Technical Details
` + "```" + `
{{.TechnicalDetails}}
` + "```" + `

## Affected URLs
{{.FormattedAffectedURLs}}

## Remediation
{{.Remediation}}

## Analysis Notes
{{.AnalysisNotes}}

## References
{{.References}}

## History
{{.FormattedHistory}}
`,
		"alert_confluence.html": `<h1>{{.AlertName}}</h1>

<div class="panel pdl">
    <div class="panelHeader" style="border-bottom-width: 0px;">
        <strong>Alert Details</strong>
    </div>
    <div class="panelContent">
        <table class="wrapped confluenceTable">
            <tbody>
                <tr>
                    <th class="confluenceTh">Alert ID</th>
                    <td class="confluenceTd">{{.AlertID}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Risk Level</th>
                    <td class="confluenceTd">{{.Risk}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">CWE</th>
                    <td class="confluenceTd"><a href="https://cwe.mitre.org/data/definitions/{{.CWEID}}.html">{{.CWEID}}</a></td>
                </tr>
                <tr>
                    <th class="confluenceTh">Status</th>
                    <td class="confluenceTd">{{.Status}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Triage Status</th>
                    <td class="confluenceTd">{{.TriageStatus}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Project</th>
                    <td class="confluenceTd">{{.Project}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Assigned To</th>
                    <td class="confluenceTd">{{.AssignedTo}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Date Added</th>
                    <td class="confluenceTd">{{.DateAdded}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Last Updated</th>
                    <td class="confluenceTd">{{.DateUpdated}}</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<h2>Description</h2>
<p>{{.Description}}</p>

<h2>Technical Details</h2>
<div class="code panel pdl">
    <div class="codeContent panelContent pdl">
        <pre class="syntaxhighlighter-pre">{{.TechnicalDetails}}</pre>
    </div>
</div>

<h2>Affected URLs</h2>
<p>{{.FormattedAffectedURLs}}</p>

<h2>Remediation</h2>
<p>{{.Remediation}}</p>

<h2>Analysis Notes</h2>
<p>{{.AnalysisNotes}}</p>

<h2>References</h2>
<p>{{.References}}</p>

<h2>History</h2>
<p>{{.FormattedHistory}}</p>
`,
		"project_obsidian.md": `---
project_name: {{.ProjectName}}
project_id: {{.ProjectID}}
date_added: {{.DateAdded}}
date_updated: {{.DateUpdated}}
owner: {{.Owner}}
---

# {{.ProjectName}}

## Project Details
- **Project ID**: {{.ProjectID}}
- **Owner**: {{.Owner}}
- **Date Added**: {{.DateAdded}}
- **Last Updated**: {{.DateUpdated}}

## Alert Summary
{{.AlertSummary}}

## Open Alerts
{{.OpenAlerts}}

## Resolved Alerts
{{.ResolvedAlerts}}

## Historical Scan Results
{{.ScanHistory}}
`,
		"project_confluence.html": `<h1>{{.ProjectName}}</h1>

<div class="panel pdl">
    <div class="panelHeader" style="border-bottom-width: 0px;">
        <strong>Project Details</strong>
    </div>
    <div class="panelContent">
        <table class="wrapped confluenceTable">
            <tbody>
                <tr>
                    <th class="confluenceTh">Project ID</th>
                    <td class="confluenceTd">{{.ProjectID}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Owner</th>
                    <td class="confluenceTd">{{.Owner}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Date Added</th>
                    <td class="confluenceTd">{{.DateAdded}}</td>
                </tr>
                <tr>
                    <th class="confluenceTh">Last Updated</th>
                    <td class="confluenceTd">{{.DateUpdated}}</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<h2>Alert Summary</h2>
{{.AlertSummary}}

<h2>Open Alerts</h2>
{{.OpenAlerts}}

<h2>Resolved Alerts</h2>
{{.ResolvedAlerts}}

<h2>Historical Scan Results</h2>
{{.ScanHistory}}
`,
	}

	for templateName, templateContent := range templates {
		templatePath := filepath.Join(kb.KBDir, TEMPLATES_DIR, templateName)
		if _, err := os.Stat(templatePath); os.IsNotExist(err) {
			err = os.WriteFile(templatePath, []byte(templateContent), 0644)
			if err != nil {
				log.Printf("Error creating template %s: %v", templateName, err)
			}
		}
	}
}

// Load a template
func (kb *DevSecOpsKB) loadTemplate(templateName string) (string, error) {
	templatePath := filepath.Join(kb.KBDir, TEMPLATES_DIR, templateName)
	content, err := os.ReadFile(templatePath)
	if err != nil {
		return "", fmt.Errorf("error loading template %s: %v", templateName, err)
	}
	return string(content), nil
}

// Fetch CWE details from MITRE
func (kb *DevSecOpsKB) fetchCWEDetails(cweid string) map[string]string {
	url := fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweid)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error fetching CWE details for %s: %v", cweid, err)
		return map[string]string{"error": err.Error(), "source": url}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Error fetching CWE details for %s: status %d", cweid, resp.StatusCode)
		return map[string]string{"error": fmt.Sprintf("HTTP status %d", resp.StatusCode), "source": url}
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("Error parsing CWE details for %s: %v", cweid, err)
		return map[string]string{"error": err.Error(), "source": url}
	}

	title := doc.Find("title").Text()
	if title == "" {
		title = fmt.Sprintf("CWE-%s", cweid)
	}

	var snippet string
	definitionDiv := doc.Find("div#Definition")
	if definitionDiv.Length() > 0 {
		snippet = strings.TrimSpace(definitionDiv.Text())
	} else {
		descriptionDiv := doc.Find("div#Description")
		if descriptionDiv.Length() > 0 {
			indentDiv := descriptionDiv.Find("div.indent")
			if indentDiv.Length() > 0 {
				snippet = strings.TrimSpace(indentDiv.Text())
			} else {
				snippet = strings.TrimSpace(descriptionDiv.Text())
			}
		} else {
			snippet = "Definition not found."
		}
	}

	return map[string]string{
		"title":   title,
		"snippet": snippet,
		"source":  url,
	}
}

// Generate a unique alert ID
func (kb *DevSecOpsKB) generateAlertID(alertData map[string]interface{}) string {
	var baseID string
	if alertID, ok := alertData["alert_id"].(string); ok && alertID != "" {
		baseID = alertID
	} else if alertName, ok := alertData["alert_name"].(string); ok && alertName != "" {
		baseID = alertName
	} else if alertType, ok := alertData["alert_type"].(string); ok && alertType != "" {
		baseID = alertType
	} else {
		baseID = "unknown_alert"
	}

	// Clean up the ID
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	baseID = strings.ToLower(re.ReplaceAllString(baseID, "_"))

	// Add timestamp for uniqueness
	timestamp := time.Now().Format("20060102150405")
	return fmt.Sprintf("%s_%s", baseID, timestamp)
}

// Ingest scan results into the KB
func (kb *DevSecOpsKB) ingestScanResults(scanResults map[string]interface{}, projectName string, scanDate string) int {
	if scanDate == "" {
		scanDate = time.Now().Format(time.RFC3339)
	}

	// Initialize project if it doesn't exist
	if _, exists := kb.Metadata.Projects[projectName]; !exists {
		re := regexp.MustCompile(`[^a-zA-Z0-9]`)
		projectID := strings.ToLower(re.ReplaceAllString(projectName, "_"))
		kb.Metadata.Projects[projectName] = Project{
			ProjectID:   projectID,
			DateAdded:   scanDate,
			DateUpdated: scanDate,
			Owner:       "Unassigned",
			Alerts:      []string{},
			Scans:       []Scan{},
		}
	}

	projectData := kb.Metadata.Projects[projectName]
	projectData.DateUpdated = scanDate

	// Add scan record
	scanID := uuid.New().String()
	alerts, _ := scanResults["alerts"].([]interface{})
	projectData.Scans = append(projectData.Scans, Scan{
		ScanID:     scanID,
		ScanDate:   scanDate,
		AlertCount: len(alerts),
	})

	// Process each alert
	for _, alertInterface := range alerts {
		alertMap, ok := alertInterface.(map[string]interface{})
		if !ok {
			continue
		}

		// Convert map to structured format for processing
		alertData := make(map[string]interface{})
		for k, v := range alertMap {
			alertData[k] = v
		}

		// Generate a unique ID for this alert instance
		alertInstanceID := kb.generateAlertID(alertData)

		// Check if this is a known alert type
		alertTypeID, _ := alertData["alert_id"].(string)
		canonicalAlert, exists := kb.CanonicalVulns[alertTypeID]

		// Extract values with defaults from canonical alert if available
		alertName, _ := alertData["alert_name"].(string)
		if alertName == "" && exists {
			alertName = canonicalAlert.AlertName
		}

		alertType, _ := alertData["alert_type"].(string)
		if alertType == "" && exists {
			alertType = canonicalAlert.AlertType
		}

		risk, _ := alertData["risk"].(string)
		if risk == "" && exists {
			risk = canonicalAlert.Risk
		}

		cweID, _ := alertData["cweid"].(string)
		if cweID == "" && exists {
			cweID = canonicalAlert.CWEID
		}

		description, _ := alertData["description"].(string)
		if description == "" && exists {
			description = canonicalAlert.Description
		}

		remediation, _ := alertData["remediation"].(string)
		if remediation == "" && exists {
			remediation = canonicalAlert.Remediation
		}

		reference, _ := alertData["reference"].(string)
		if reference == "" && exists {
			reference = canonicalAlert.Reference
		}

		evidence, _ := alertData["evidence"].(string)
		if evidence == "" {
			evidence, _ = alertData["details"].(string)
			if evidence == "" {
				evidence = "{}"
			}
		}

		var affectedURLs []string
		if urlsInterface, ok := alertData["urls"].([]interface{}); ok {
			for _, urlInterface := range urlsInterface {
				if url, ok := urlInterface.(string); ok {
					affectedURLs = append(affectedURLs, url)
				}
			}
		}

		// Enrich with CWE details if available
		var cweDetails map[string]string
		if cweID != "" {
			cweDetails = kb.fetchCWEDetails(cweID)
		}

		// Create alert data structure
		alert := Alert{
			AlertInstanceID:  alertInstanceID,
			AlertID:          alertTypeID,
			AlertName:        alertName,
			AlertType:        alertType,
			Risk:             risk,
			CWEID:            cweID,
			CWEDetails:       cweDetails,
			Description:      description,
			Remediation:      remediation,
			TechnicalDetails: evidence,
			AffectedURLs:     affectedURLs,
			References:       reference,
			Status:           "new",
			TriageStatus:     "pending",
			Project:          projectName,
			AssignedTo:       "Unassigned",
			DateAdded:        scanDate,
			DateUpdated:      scanDate,
			History: []map[string]interface{}{
				{
					"timestamp": scanDate,
					"action":    "added",
					"details":   fmt.Sprintf("Alert added from scan %s", scanID),
				},
			},
			AnalysisNotes: "",
		}

		// Add to project alerts
		projectData.Alerts = append(projectData.Alerts, alertInstanceID)

		// Add to global alerts
		kb.Metadata.Alerts[alertInstanceID] = alert

		// Generate KB entry
		kb.generateKBEntry(alert)
	}

	// Update stats
	kb.Metadata.Stats.TotalAlerts += len(alerts)

	// Save metadata
	kb.Metadata.Projects[projectName] = projectData
	kb.saveMetadata()

	// Generate project KB entry
	kb.generateProjectKBEntry(projectName)

	log.Printf("Ingested %d alerts for project %s", len(alerts), projectName)
	return len(alerts)
}

// Generate a KB entry for an alert
func (kb *DevSecOpsKB) generateKBEntry(alert Alert) string {
	// Prepare template data
	templateData := struct {
		Alert
		FormattedAffectedURLs string
		FormattedHistory      string
	}{
		Alert: alert,
	}

	// Format affected URLs
	if len(alert.AffectedURLs) > 0 {
		if kb.FormatType == "obsidian" {
			var urls []string
			for _, url := range alert.AffectedURLs {
				urls = append(urls, fmt.Sprintf("- %s", url))
			}
			templateData.FormattedAffectedURLs = strings.Join(urls, "\n")
		} else { // confluence
			var urls []string
			for _, url := range alert.AffectedURLs {
				urls = append(urls, fmt.Sprintf("<li>%s</li>", url))
			}
			templateData.FormattedAffectedURLs = "<ul>" + strings.Join(urls, "") + "</ul>"
		}
	} else {
		templateData.FormattedAffectedURLs = "No affected URLs."
	}

	// Format history
	if len(alert.History) > 0 {
		if kb.FormatType == "obsidian" {
			var historyEntries []string
			for _, entry := range alert.History {
				timestamp, _ := entry["timestamp"].(string)
				action, _ := entry["action"].(string)
				details, _ := entry["details"].(string)
				historyEntries = append(historyEntries, fmt.Sprintf("- %s: %s - %s", timestamp, action, details))
			}
			templateData.FormattedHistory = strings.Join(historyEntries, "\n")
		} else { // confluence
			var historyEntries []string
			historyEntries = append(historyEntries, "<table><tr><th>Timestamp</th><th>Action</th><th>Details</th></tr>")
			for _, entry := range alert.History {
				timestamp, _ := entry["timestamp"].(string)
				action, _ := entry["action"].(string)
				details, _ := entry["details"].(string)
				historyEntries = append(historyEntries, fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>", timestamp, action, details))
			}
			historyEntries = append(historyEntries, "</table>")
			templateData.FormattedHistory = strings.Join(historyEntries, "")
		}
	} else {
		templateData.FormattedHistory = "No history available."
	}

	// Load and render template
	var templateContent string
	var outputFile string
	var err error

	if kb.FormatType == "obsidian" {
		templateContent, err = kb.loadTemplate("alert_obsidian.md")
		outputFile = filepath.Join(kb.KBDir, "alerts", fmt.Sprintf("%s.md", alert.AlertInstanceID))
	} else { // confluence
		templateContent, err = kb.loadTemplate("alert_confluence.html")
		outputFile = filepath.Join(kb.KBDir, "alerts", fmt.Sprintf("%s.html", alert.AlertInstanceID))
	}

	if err != nil {
		log.Printf("Error loading template: %v", err)
		return ""
	}

	tmpl, err := template.New("alert").Parse(templateContent)
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		return ""
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		return ""
	}

	err = os.WriteFile(outputFile, buf.Bytes(), 0644)
	if err != nil {
		log.Printf("Error writing KB entry: %v", err)
		return ""
	}

	log.Printf("Generated KB entry for alert %s", alert.AlertInstanceID)
	return outputFile
}

// Generate a KB entry for a project
func (kb *DevSecOpsKB) generateProjectKBEntry(projectName string) string {
	projectData, exists := kb.Metadata.Projects[projectName]
	if !exists {
		log.Printf("Project %s not found in KB", projectName)
		return ""
	}

	// Get all alerts for this project
	var projectAlerts []Alert
	for _, alertID := range projectData.Alerts {
		if alert, exists := kb.Metadata.Alerts[alertID]; exists {
			projectAlerts = append(projectAlerts, alert)
		}
	}

	// Separate open and resolved alerts
	var openAlerts, resolvedAlerts []Alert
	for _, alert := range projectAlerts {
		if alert.Status != "resolved" {
			openAlerts = append(openAlerts, alert)
		} else {
			resolvedAlerts = append(resolvedAlerts, alert)
		}
	}

	// Count alerts by risk level
	riskLevels := map[string]int{
		"High":          0,
		"Medium":        0,
		"Low":           0,
		"Informational": 0,
	}

	for _, alert := range projectAlerts {
		risk := alert.Risk
		if risk == "" {
			risk = "Informational"
		}
		if _, exists := riskLevels[risk]; exists {
			riskLevels[risk]++
		} else {
			riskLevels["Informational"]++
		}
	}

	// Prepare template data
	templateData := struct {
		ProjectName    string
		ProjectID      string
		DateAdded      string
		DateUpdated    string
		Owner          string
		AlertSummary   string
		OpenAlerts     string
		ResolvedAlerts string
		ScanHistory    string
	}{
		ProjectName: projectName,
		ProjectID:   projectData.ProjectID,
		DateAdded:   projectData.DateAdded,
		DateUpdated: projectData.DateUpdated,
		Owner:       projectData.Owner,
	}

	// Format alert summary
	if kb.FormatType == "obsidian" {
		var summaryEntries []string
		for risk, count := range riskLevels {
			summaryEntries = append(summaryEntries, fmt.Sprintf("- **%s**: %d", risk, count))
		}
		templateData.AlertSummary = strings.Join(summaryEntries, "\n")
	} else { // confluence
		var summaryEntries []string
		summaryEntries = append(summaryEntries, "<table><tr><th>Risk Level</th><th>Count</th></tr>")
		for risk, count := range riskLevels {
			summaryEntries = append(summaryEntries, fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", risk, count))
		}
		summaryEntries = append(summaryEntries, "</table>")
		templateData.AlertSummary = strings.Join(summaryEntries, "")
	}

	// Format open alerts
	if len(openAlerts) > 0 {
		if kb.FormatType == "obsidian" {
			var alertEntries []string
			for _, alert := range openAlerts {
				alertEntries = append(alertEntries, fmt.Sprintf("- [%s](%s.md) - %s risk - %s",
					alert.AlertName, alert.AlertInstanceID, alert.Risk, alert.TriageStatus))
			}
			templateData.OpenAlerts = strings.Join(alertEntries, "\n")
		} else { // confluence
			var alertEntries []string
			alertEntries = append(alertEntries, "<table><tr><th>Alert</th><th>Risk</th><th>Status</th></tr>")
			for _, alert := range openAlerts {
				alertEntries = append(alertEntries, fmt.Sprintf("<tr><td><a href='%s.html'>%s</a></td><td>%s</td><td>%s</td></tr>",
					alert.AlertInstanceID, alert.AlertName, alert.Risk, alert.TriageStatus))
			}
			alertEntries = append(alertEntries, "</table>")
			templateData.OpenAlerts = strings.Join(alertEntries, "")
		}
	} else {
		templateData.OpenAlerts = "No open alerts."
	}

	// Format resolved alerts
	if len(resolvedAlerts) > 0 {
		if kb.FormatType == "obsidian" {
			var alertEntries []string
			for _, alert := range resolvedAlerts {
				alertEntries = append(alertEntries, fmt.Sprintf("- [%s](%s.md) - %s risk - %s",
					alert.AlertName, alert.AlertInstanceID, alert.Risk, alert.TriageStatus))
			}
			templateData.ResolvedAlerts = strings.Join(alertEntries, "\n")
		} else { // confluence
			var alertEntries []string
			alertEntries = append(alertEntries, "<table><tr><th>Alert</th><th>Risk</th><th>Status</th></tr>")
			for _, alert := range resolvedAlerts {
				alertEntries = append(alertEntries, fmt.Sprintf("<tr><td><a href='%s.html'>%s</a></td><td>%s</td><td>%s</td></tr>",
					alert.AlertInstanceID, alert.AlertName, alert.Risk, alert.TriageStatus))
			}
			alertEntries = append(alertEntries, "</table>")
			templateData.ResolvedAlerts = strings.Join(alertEntries, "")
		}
	} else {
		templateData.ResolvedAlerts = "No resolved alerts."
	}

	// Format scan history
	if len(projectData.Scans) > 0 {
		if kb.FormatType == "obsidian" {
			var scanEntries []string
			for _, scan := range projectData.Scans {
				scanEntries = append(scanEntries, fmt.Sprintf("- %s: %d alerts", scan.ScanDate, scan.AlertCount))
			}
			templateData.ScanHistory = strings.Join(scanEntries, "\n")
		} else { // confluence
			var scanEntries []string
			scanEntries = append(scanEntries, "<table><tr><th>Date</th><th>Alert Count</th></tr>")
			for _, scan := range projectData.Scans {
				scanEntries = append(scanEntries, fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", scan.ScanDate, scan.AlertCount))
			}
			scanEntries = append(scanEntries, "</table>")
			templateData.ScanHistory = strings.Join(scanEntries, "")
		}
	} else {
		templateData.ScanHistory = "No scan history."
	}

	// Load and render template
	var templateContent string
	var outputFile string
	var err error

	if kb.FormatType == "obsidian" {
		templateContent, err = kb.loadTemplate("project_obsidian.md")
		outputFile = filepath.Join(kb.KBDir, "projects", fmt.Sprintf("%s.md", projectData.ProjectID))
	} else { // confluence
		templateContent, err = kb.loadTemplate("project_confluence.html")
		outputFile = filepath.Join(kb.KBDir, "projects", fmt.Sprintf("%s.html", projectData.ProjectID))
	}

	if err != nil {
		log.Printf("Error loading template: %v", err)
		return ""
	}

	tmpl, err := template.New("project").Parse(templateContent)
	if err != nil {
		log.Printf("Error parsing template: %v", err)
		return ""
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, templateData)
	if err != nil {
		log.Printf("Error executing template: %v", err)
		return ""
	}

	err = os.WriteFile(outputFile, buf.Bytes(), 0644)
	if err != nil {
		log.Printf("Error writing KB entry: %v", err)
		return ""
	}

	log.Printf("Generated KB entry for project %s", projectName)
	return outputFile
}

// Generate index files for the KB
func (kb *DevSecOpsKB) generateIndex() {
	if kb.FormatType == "obsidian" {
		// Create Obsidian index file
		var indexContent strings.Builder
		indexContent.WriteString("# DevSecOps Knowledge Base\n\n")

		// Add projects section
		indexContent.WriteString("## Projects\n\n")
		for projectName, projectData := range kb.Metadata.Projects {
			indexContent.WriteString(fmt.Sprintf("- [%s](projects/%s.md)\n", projectName, projectData.ProjectID))
		}

		// Add recent alerts section
		indexContent.WriteString("\n## Recent Alerts\n\n")

		// Get all alerts and sort them by date updated
		var allAlerts []Alert
		for _, alert := range kb.Metadata.Alerts {
			allAlerts = append(allAlerts, alert)
		}

		// Sort alerts by date updated (most recent first)
		sort.Slice(allAlerts, func(i, j int) bool {
			return allAlerts[i].DateUpdated > allAlerts[j].DateUpdated
		})

		// Take the 10 most recent alerts
		recentAlerts := allAlerts
		if len(recentAlerts) > 10 {
			recentAlerts = recentAlerts[:10]
		}

		for _, alert := range recentAlerts {
			indexContent.WriteString(fmt.Sprintf("- [%s](alerts/%s.md) - %s - %s risk - %s\n",
				alert.AlertName, alert.AlertInstanceID, alert.Project, alert.Risk, alert.Status))
		}

		// Add statistics section
		indexContent.WriteString("\n## Statistics\n\n")
		indexContent.WriteString(fmt.Sprintf("- **Total Alerts**: %d\n", kb.Metadata.Stats.TotalAlerts))
		indexContent.WriteString(fmt.Sprintf("- **Triaged Alerts**: %d\n", kb.Metadata.Stats.TriagedAlerts))
		indexContent.WriteString(fmt.Sprintf("- **False Positives**: %d\n", kb.Metadata.Stats.FalsePositives))
		indexContent.WriteString(fmt.Sprintf("- **Accepted Risks**: %d\n", kb.Metadata.Stats.AcceptedRisks))
		indexContent.WriteString(fmt.Sprintf("- **Fixed Vulnerabilities**: %d\n", kb.Metadata.Stats.FixedVulnerabilities))

		// Write the index file
		indexFile := filepath.Join(kb.KBDir, "index.md")
		err := os.WriteFile(indexFile, []byte(indexContent.String()), 0644)
		if err != nil {
			log.Printf("Error writing index file: %v", err)
		}
	} else { // confluence
		// Create Confluence index file
		var indexContent strings.Builder
		indexContent.WriteString("<h1>DevSecOps Knowledge Base</h1>\n\n")

		// Add projects section
		indexContent.WriteString("<h2>Projects</h2>\n\n<ul>\n")
		for projectName, projectData := range kb.Metadata.Projects {
			indexContent.WriteString(fmt.Sprintf("<li><a href='projects/%s.html'>%s</a></li>\n", projectData.ProjectID, projectName))
		}
		indexContent.WriteString("</ul>\n\n")

		// Add recent alerts section
		indexContent.WriteString("<h2>Recent Alerts</h2>\n\n<table>\n")
		indexContent.WriteString("<tr><th>Alert</th><th>Project</th><th>Risk</th><th>Status</th></tr>\n")

		// Get all alerts and sort them by date updated
		var allAlerts []Alert
		for _, alert := range kb.Metadata.Alerts {
			allAlerts = append(allAlerts, alert)
		}

		// Sort alerts by date updated (most recent first)
		sort.Slice(allAlerts, func(i, j int) bool {
			return allAlerts[i].DateUpdated > allAlerts[j].DateUpdated
		})

		// Take the 10 most recent alerts
		recentAlerts := allAlerts
		if len(recentAlerts) > 10 {
			recentAlerts = recentAlerts[:10]
		}

		for _, alert := range recentAlerts {
			indexContent.WriteString(fmt.Sprintf("<tr><td><a href='alerts/%s.html'>%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
				alert.AlertInstanceID, alert.AlertName, alert.Project, alert.Risk, alert.Status))
		}
		indexContent.WriteString("</table>\n\n")

		// Add statistics section
		indexContent.WriteString("<h2>Statistics</h2>\n\n<table>\n")
		indexContent.WriteString("<tr><th>Metric</th><th>Value</th></tr>\n")
		indexContent.WriteString(fmt.Sprintf("<tr><td>Total Alerts</td><td>%d</td></tr>\n", kb.Metadata.Stats.TotalAlerts))
		indexContent.WriteString(fmt.Sprintf("<tr><td>Triaged Alerts</td><td>%d</td></tr>\n", kb.Metadata.Stats.TriagedAlerts))
		indexContent.WriteString(fmt.Sprintf("<tr><td>False Positives</td><td>%d</td></tr>\n", kb.Metadata.Stats.FalsePositives))
		indexContent.WriteString(fmt.Sprintf("<tr><td>Accepted Risks</td><td>%d</td></tr>\n", kb.Metadata.Stats.AcceptedRisks))
		indexContent.WriteString(fmt.Sprintf("<tr><td>Fixed Vulnerabilities</td><td>%d</td></tr>\n", kb.Metadata.Stats.FixedVulnerabilities))
		indexContent.WriteString("</table>\n")

		// Write the index file
		indexFile := filepath.Join(kb.KBDir, "index.html")
		err := os.WriteFile(indexFile, []byte(indexContent.String()), 0644)
		if err != nil {
			log.Printf("Error writing index file: %v", err)
		}
	}

	log.Printf("Generated KB index")
}

// Process ZAP scan results
func (kb *DevSecOpsKB) processZAPResults(zapFile string, projectName string) int {
	// Read the ZAP report file
	zapData, err := os.ReadFile(zapFile)
	if err != nil {
		log.Printf("Error reading ZAP file: %v", err)
		return 0
	}

	// Try to parse the ZAP report
	var zapReport ZAPReport
	err = json.Unmarshal(zapData, &zapReport)
	if err != nil {
		// Not the standard ZAP report format, try other formats
		var genericMap map[string]interface{}
		err = json.Unmarshal(zapData, &genericMap)
		if err != nil {
			log.Printf("Error parsing ZAP file: %v", err)
			return 0
		}

		// Extract alerts based on the format
		var alerts []interface{}

		// Check for "site" format
		if sites, ok := genericMap["site"].([]interface{}); ok {
			// Traditional ZAP JSON report format
			for _, siteInterface := range sites {
				site, ok := siteInterface.(map[string]interface{})
				if !ok {
					continue
				}

				siteAlerts, ok := site["alerts"].([]interface{})
				if !ok {
					continue
				}

				for _, alertInterface := range siteAlerts {
					alert, ok := alertInterface.(map[string]interface{})
					if !ok {
						continue
					}

					// Process instances
					var urls []string
					var evidence string

					instances, ok := alert["instances"].([]interface{})
					if ok {
						for _, instanceInterface := range instances {
							instance, ok := instanceInterface.(map[string]interface{})
							if !ok {
								continue
							}

							if uri, ok := instance["uri"].(string); ok {
								urls = append(urls, uri)
							}

							if e, ok := instance["evidence"].(string); ok && e != "" {
								if evidence != "" {
									evidence += "\n"
								}
								evidence += e
							}
						}
					}

					// Create a standardized alert
					standardAlert := map[string]interface{}{
						"alert_id":    alert["pluginId"],
						"alert_name":  alert["name"],
						"alert_type":  alert["name"],
						"risk":        extractRiskLevel(alert["riskdesc"]),
						"cweid":       alert["cweid"],
						"description": alert["desc"],
						"remediation": alert["solution"],
						"reference":   alert["reference"],
						"evidence":    evidence,
						"urls":        urls,
					}

					alerts = append(alerts, standardAlert)
				}
			}
		} else if vulnerabilities, ok := genericMap["vulnerabilities"].([]interface{}); ok {
			// Process vulnerabilities format
			for _, vulnInterface := range vulnerabilities {
				vuln, ok := vulnInterface.(map[string]interface{})
				if !ok {
					continue
				}

				// Create a standardized alert
				standardAlert := map[string]interface{}{
					"alert_id":    vuln["pluginId"],
					"alert_name":  vuln["name"],
					"alert_type":  vuln["name"],
					"risk":        vuln["risk"],
					"cweid":       vuln["cweid"],
					"description": vuln["description"],
					"remediation": vuln["solution"],
					"reference":   vuln["reference"],
					"evidence":    vuln["evidence"],
					"urls":        []string{fmt.Sprintf("%v", vuln["url"])},
				}

				alerts = append(alerts, standardAlert)
			}
		} else if directAlerts, ok := genericMap["alerts"].([]interface{}); ok {
			// Direct alerts format
			alerts = directAlerts
		} else {
			log.Printf("Unsupported ZAP report format")
			return 0
		}

		// Create scan results structure
		scanResults := map[string]interface{}{
			"tool":      "ZAP",
			"scan_date": time.Now().Format(time.RFC3339),
			"alerts":    alerts,
		}

		// Ingest the processed results
		return kb.ingestScanResults(scanResults, projectName, "")
	}

	// Standard ZAP report format processing
	var alerts []interface{}

	for _, site := range zapReport.Site {
		for _, alert := range site.Alerts {
			var urls []string
			var evidence string

			for _, instance := range alert.Instances {
				if instance.URI != "" {
					urls = append(urls, instance.URI)
				}

				if instance.Evidence != "" {
					if evidence != "" {
						evidence += "\n"
					}
					evidence += instance.Evidence
				}
			}

			// Create a standardized alert
			standardAlert := map[string]interface{}{
				"alert_id":    alert.PluginID,
				"alert_name":  alert.Name,
				"alert_type":  alert.Name,
				"risk":        extractRiskLevel(alert.RiskDesc),
				"cweid":       alert.CWEID,
				"description": alert.Description,
				"remediation": alert.Solution,
				"reference":   alert.Reference,
				"evidence":    evidence,
				"urls":        urls,
			}

			alerts = append(alerts, standardAlert)
		}
	}

	// Create scan results structure
	scanResults := map[string]interface{}{
		"tool":      "ZAP",
		"scan_date": time.Now().Format(time.RFC3339),
		"alerts":    alerts,
	}

	// Ingest the processed results
	return kb.ingestScanResults(scanResults, projectName, "")
}

// Extract risk level from ZAP risk description
func extractRiskLevel(riskDesc interface{}) string {
	if riskDesc == nil {
		return "Unknown"
	}

	riskStr, ok := riskDesc.(string)
	if !ok {
		return "Unknown"
	}

	// ZAP risk descriptions are often in the format "High (Medium)" or just "High"
	parts := strings.SplitN(riskStr, " ", 2)
	if len(parts) > 0 {
		return parts[0]
	}

	return "Unknown"
}

// Initialize the KB with canonical ZAP alerts
func (kb *DevSecOpsKB) initializeWithCanonicalAlerts() bool {
	// Run init.py to generate canonical_vulns.json if it doesn't exist
	canonicalVulnsPath := filepath.Join(kb.KBDir, CANONICAL_VULNS_FILE)
	if _, err := os.Stat(canonicalVulnsPath); os.IsNotExist(err) {
		log.Printf("Canonical vulnerabilities file not found. Attempting to generate...")

		// Note: This part would normally call the init.py script
		// Since this is a Go program, we'd need to either include the script's functionality
		// or have a way to call the Python script from Go

		// For this example, we'll just provide a placeholder message
		log.Printf("IMPORTANT: You need to run init.py manually to generate canonical_vulns.json")
		log.Printf("Then place it in the KB directory at: %s", canonicalVulnsPath)
		return false
	}

	// Load canonical vulnerabilities
	vulnsFile, err := os.ReadFile(canonicalVulnsPath)
	if err != nil {
		log.Printf("Error reading canonical vulnerabilities: %v", err)
		return false
	}

	var vulnsData CanonicalVulns
	err = json.Unmarshal(vulnsFile, &vulnsData)
	if err != nil {
		log.Printf("Error parsing canonical vulnerabilities: %v", err)
		return false
	}

	// Create a "ZAP Alerts Reference" project for all canonical alerts
	projectName := "ZAP Alerts Reference"

	// Convert canonical vulnerabilities to alerts format
	var alerts []interface{}
	for _, vuln := range vulnsData.Vulnerabilities {
		alert := map[string]interface{}{
			"alert_id":    vuln.AlertID,
			"alert_name":  vuln.AlertName,
			"alert_type":  vuln.AlertType,
			"risk":        vuln.Risk,
			"cweid":       vuln.CWEID,
			"description": vuln.Description,
			"remediation": vuln.Remediation,
			"reference":   vuln.Reference,
			"evidence":    "",         // No evidence in canonical definitions
			"urls":        []string{}, // No URLs in canonical definitions
		}
		alerts = append(alerts, alert)
	}

	// Create scan results structure
	scanResults := map[string]interface{}{
		"tool":      "ZAP",
		"scan_date": time.Now().Format(time.RFC3339),
		"alerts":    alerts,
	}

	// Ingest the canonical alerts as reference
	alertCount := kb.ingestScanResults(scanResults, projectName, "")

	// Generate index
	kb.generateIndex()

	log.Printf("KB initialization complete. Added %d canonical alerts.", alertCount)
	return true
}

func main() {
	// Parse command line flags
	var (
		initialize  = flag.Bool("initialize", false, "Initialize the KB with canonical ZAP alerts")
		update      = flag.Bool("update", false, "Update the KB with new scan results")
		inputFile   = flag.String("input", "", "Input scan results file (required for update)")
		formatType  = flag.String("format", "obsidian", "Output format (obsidian or confluence)")
		outputDir   = flag.String("output", "devsecops_kb", "Output directory for the KB")
		projectName = flag.String("project", "", "Project name (required for update)")
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

	log.Printf("KB is available at %s", *outputDir)
}
