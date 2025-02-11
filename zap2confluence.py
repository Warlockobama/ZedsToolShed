#!/usr/bin/env python3
import requests
import json
import os
import sys
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

# ============================================
# HELPER FUNCTIONS
# ============================================

def load_config(config_file="config.json"):
    """Load configuration from a JSON file."""
    if not os.path.exists(config_file):
        print(f"Configuration file {config_file} not found!")
        sys.exit(1)
    with open(config_file, "r") as f:
        return json.load(f)

def truncate_text(text, max_length):
    """Truncate text to max_length characters if needed."""
    if not text:
        return ""
    if len(text) > max_length:
        return text[:max_length] + "\n[Truncated...]"
    return text

def escape_markdown(text):
    """Escape characters that might break Markdown formatting."""
    if isinstance(text, str):
        return text.replace("|", "\\|")
    return text

# ============================================
# ZAP DISCOVERY DATA FUNCTIONS
# ============================================

def get_zap_urls(zap_base_url, zap_api_key=""):
    """
    Retrieve all discovered URLs from ZAP using the core/view/urls endpoint.
    """
    endpoint = f"{zap_base_url}/JSON/core/view/urls/"
    params = {}
    if zap_api_key:
        params["apikey"] = zap_api_key
    try:
        response = requests.get(endpoint, params=params)
        response.raise_for_status()
        # Expected response is a JSON object with a key "urls"
        return response.json().get("urls", [])
    except requests.RequestException as e:
        print(f"Error retrieving URLs from ZAP: {e}")
        return []

def get_discovery_info(config):
    """
    Use ZAP's URLs API to compute:
      - Number of dynamic URLs (with query parameters)
      - Number of static URLs (without query parameters)
      - Total number of parameters (across dynamic URLs)
      - Number of unique parameter names
    Returns a Markdown-formatted string.
    """
    zap = config.get("zap", {})
    urls = get_zap_urls(zap.get("base_url"), zap.get("api_key"))
    
    dynamic_urls = []
    static_urls = []
    total_params = 0
    unique_params = set()

    for url in urls:
        parsed = urlparse(url)
        qs = parsed.query
        if qs:
            dynamic_urls.append(url)
            params = parse_qs(qs)
            total_params += sum(len(values) for values in params.values())
            for param in params:
                unique_params.add(param)
        else:
            static_urls.append(url)

    md = ""
    md += f"- **Number of dynamic URLs:** {len(dynamic_urls)}\n"
    md += f"- **Number of static URLs:** {len(static_urls)}\n"
    md += f"- **Number of parameters:** {total_params}\n"
    md += f"- **Number of unique parameter names:** {len(unique_params)}\n\n"
    md += "(*Insert a screenshot of the site map here*)\n\n"
    return md

# ============================================
# ALERT INSTANCE FORMATTING
# ============================================

def format_alert_instance(item, idx, config):
    """
    Format a single alert instance as a collapsible Markdown section.
    Includes all relevant fields and, optionally, HTTP request/response details.
    """
    md = f"<details>\n<summary>Instance {idx}</summary>\n\n"
    md += f"**Description:** {item.get('description', 'No Description')}\n\n"
    url_raw = item.get("url", "No URL")
    url_md = f"[Link]({url_raw})" if url_raw != "No URL" else url_raw
    md += f"**URL:** {url_md}\n\n"
    md += f"**Parameter:** {item.get('param', 'N/A')}\n\n"
    md += f"**Attack:** {item.get('attack', 'N/A')}\n\n"
    md += f"**Evidence:** {item.get('evidence', 'No Evidence')}\n\n"
    md += f"**Solution:** {item.get('solution', 'No Solution')}\n\n"
    md += f"**Reference:** {item.get('reference', 'No Reference')}\n\n"
    md += f"**CWE ID:** {item.get('cweid', 'N/A')}\n\n"
    wascid = item.get("wascid", "N/A")
    try:
        if int(wascid) == -1:
            wascid = "N/A"
    except:
        pass
    md += f"**WASC ID:** {wascid}\n\n"

    if config.get("include_request") and item.get("request"):
        req = truncate_text(item.get("request"), config.get("request_max_length", 5000))
        md += "**Request:**\n\n"
        md += "```http\n" + req + "\n```\n\n"
    if config.get("include_response") and item.get("response"):
        resp = truncate_text(item.get("response"), config.get("response_max_length", 5000))
        md += "**Response:**\n\n"
        md += "```http\n" + resp + "\n```\n\n"

    md += "</details>\n\n"
    return md

# ============================================
# GROUPING & SORTING ALERTS BY SEVERITY
# ============================================
    
def summary_sort_key(item):
    """
    Define a sort key for alert groups:
      1. By severity (High -> Medium -> Low -> Informational)
      2. Then by number of unique endpoints (descending)
      3. Then alphabetically by alert name.
    """
    ((alert_name, risk), items) = item
    severity_order = {"high": 1, "medium": 2, "low": 3, "informational": 4}
    sev_val = severity_order.get(risk.lower(), 5)
    endpoints = len(set(x.get("url", "No URL") for x in items))
    return (sev_val, -endpoints, alert_name.lower())

def format_detailed_findings_by_severity(alerts, config):
    """
    Group alerts by severity (using the 'risk' field) and then by alert name.
    For each alert group:
      - If there are >5 unique endpoints, the section is wrapped in a collapsible <details> block.
      - High and Medium alerts are shown with full details (each instance is collapsible).
      - Low/Informational alerts are shown as summary lines.
    Returns the Markdown-formatted string.
    """
    # First, group by (alert_name, risk)
    grouped_alerts = defaultdict(list)
    for alert in alerts:
        key = (alert.get("alert", "Unknown Alert"), alert.get("risk", "N/A"))
        grouped_alerts[key].append(alert)
    
    # Now re-group by severity (risk) in lowercase
    severity_groups = defaultdict(list)
    for (alert_name, risk), items in grouped_alerts.items():
        sev = risk.lower()
        severity_groups[sev].append((alert_name, items))
    
    # Define desired severity order
    severity_order = ["high", "medium", "low", "informational"]
    md = ""
    for sev in severity_order:
        if sev in severity_groups:
            md += f"### {sev.capitalize()} Severity Alerts\n\n"
            # Sort the alert groups alphabetically by alert name within the same severity
            for alert_name, items in sorted(severity_groups[sev], key=lambda x: x[0].lower()):
                endpoints = set(item.get("url", "No URL") for item in items)
                section = f"## {alert_name} (Risk: {sev.capitalize()})\n\n"
                if len(endpoints) > 5:
                    section = f"<details>\n<summary>{section.strip()} (Click to expand details)</summary>\n\n" + section + "\n</details>\n\n"
                if sev in ["high", "medium"]:
                    total = len(items)
                    section += f"Total instances: {total}\n\n"
                    max_inst = config.get("max_instances_per_alert")
                    if max_inst and total > max_inst:
                        section += f"Showing first {max_inst} of {total} instances:\n\n"
                        instance_list = items[:max_inst]
                    else:
                        instance_list = items
                    for idx, item in enumerate(instance_list, start=1):
                        section += format_alert_instance(item, idx, config)
                else:
                    total = len(items)
                    section += f"Total instances: {total}\n\n"
                    section += "Summary:\n\n"
                    for item in items:
                        desc = item.get("description", "No Description")
                        url = item.get("url", "No URL")
                        section += f"- **Description:** {desc} | **URL:** {url}\n"
                    section += "\n"
                md += section
    return md

# ============================================
# REPORT MODE FORMATTER
# ============================================

def format_report_markdown(alerts, config):
    """
    Format alerts into a full security assessment report in Markdown.
    The report includes:
      - Introduction
      - Summary
      - Discovery (using ZAP results)
      - Active Scan & Audit Findings
      - Detailed Findings (grouped by severity)
    """
    # Compute overall counts for the summary
    high_count = sum(1 for alert in alerts if alert.get("risk", "").lower() == "high")
    medium_count = sum(1 for alert in alerts if alert.get("risk", "").lower() == "medium")
    endpoints = set(alert.get("url") for alert in alerts if alert.get("url"))
    endpoints_count = len(endpoints)
    
    md = "# Security Assessment Template | Jan 2025\n\n"
    
    # Introduction
    md += "## Introduction\n\n"
    md += (
        "The Security Team evaluated the `<Application Under Test>` hosted in `<Test/Impl>` environment."
        "The overall approach for this assessment is outlined in the `<Security Test Plan and Engagement Form>`. "
        "Tools selected for the assessment include **OWASP ZAP**. Testing took place from **01 Jan 2025** to **31 Jan 2025**.\n\n"
    )
    
    # Summary
    md += "## Summary\n\n"
    md += f"-The initial ZAP DAST Scan found **{high_count}** High severity issues and **{medium_count}** Medium severity issues across **{endpoints_count}** endpoints.\n"
    md += "The team recommends implementing fixes as described in the remediation recommendations section.\n\n"
    
    # Findings Summary Table (sorted by severity, then number of endpoints, then alphabetically)
    md += "### Findings Summary\n\n"
    md += "| Finding | Severity | Instances Found | Associated NIST 800-53r5 Control |\n" # TODO: Add translation layer for NIST controls based on CWE/WASC
    md += "|---------|---------|-----------------|----------------------------------|\n"
    # Group by (alert_name, risk)
    grouped_alerts = defaultdict(list)
    for alert in alerts:
        key = (alert.get("alert", "Unknown Alert"), alert.get("risk", "N/A"))
        grouped_alerts[key].append(alert)
    for (alert_name, risk), items in sorted(grouped_alerts.items(), key=summary_sort_key):
        md += f"| {alert_name} | {risk} | {len(items)} | TBD |\n"
    md += "\n"
    
    # Discovery Section
    md += "## Discovery\n\n"
    md += (
        "The Security Team began the assessment by performing **discovery scans**, starting with unauthenticated service discovery "
        "followed by authenticated application-level scanning. ZAP crawling, spidering, and content discovery scans were performed.\n\n"
    )
    md += "Results of the discovery scans using **OWASP ZAP**:\n\n"
    md += get_discovery_info(config)
    
    # Active Scan & Audit Findings Table (using same sort order)
    md += "## Active Scan & Audit Findings\n\n"
    md += "| Name | Risk | Instances Found | MM/YY Tested |\n"
    md += "|------|------|-----------------|---------------------|\n"
    for (alert_name, risk), items in sorted(grouped_alerts.items(), key=summary_sort_key):
        test_urls = "<br>".join(item.get("url", "No URL") for item in items)
        md += f"| {alert_name} | {risk} | {len(items)} | {test_urls} | 0 |\n"
    md += "\n"
    
    # Detailed Findings (grouped by severity)
    md += "## Detailed Findings\n\n"
    md += format_detailed_findings_by_severity(alerts, config)
    
    return md

# ============================================
# KB MODE FORMATTER
# ============================================
    
def format_kb_markdown(alerts, config):
    """
    Format alerts for a knowledge base update in Markdown.
    In KB mode, alerts are grouped by severity and then by alert type.
    High/Medium alerts are shown with full details and Low/Informational as summaries.
    """
    md = "# Confluence KB - ZAP Alerts\n\n"
    md += "## Overview\n\n"
    md += (
        "This knowledge base document tracks all instances of ZAP alerts for triage purposes. "
        "Analysts should review the details for each alert type and use the provided HTTP request/response information for further investigation.\n\n"
    )
    md += "## Alert Summary\n\n"
    # Group by (alert_name, risk)
    grouped_alerts = defaultdict(list)
    for alert in alerts:
        key = (alert.get("alert", "Unknown Alert"), alert.get("risk", "N/A"))
        grouped_alerts[key].append(alert)
    for (alert_name, risk), items in sorted(grouped_alerts.items(), key=summary_sort_key):
        md += f"- **{alert_name} (Risk: {risk})**: {len(items)} instance(s)\n"
    md += "\n---\n\n"
    
    # Detailed KB Entries: use the same severity grouping function
    md += format_detailed_findings_by_severity(alerts, config)
    
    return md

# ============================================
# CONFLUENCE PAGE CREATION
# ============================================
    
def create_confluence_page(html_content, config):
    """
    Publish the provided content to Confluence as a new page using the REST API.
    Confluence expects the content in its "storage" format.
    """
    confluence = config.get("confluence", {})
    url = f"{confluence.get('base_url')}/rest/api/content/"
    headers = {"Content-Type": "application/json"}
    auth = (confluence.get("username"), confluence.get("api_token"))
    data = {
        "type": "page",
        "title": confluence.get("page_title", "ZAP Report"),
        "space": {"key": confluence.get("space_key")},
        "body": {
            "storage": {
                "value": html_content,
                "representation": "storage"
            }
        }
    }
    try:
        response = requests.post(url, auth=auth, headers=headers, data=json.dumps(data))
        response.raise_for_status()
        print("Successfully created Confluence page.")
        result = response.json()
        page_id = result.get("id")
        if page_id:
            print(f"Page ID: {page_id}")
    except requests.RequestException as e:
        print(f"Error creating Confluence page: {e}")
        if response is not None:
            print("Response:", response.text)

# ============================================
# ZAP ALERT RETRIEVAL
# ============================================
    
def get_zap_alerts_data(config):
    """
    Connect to OWASP ZAP's API and retrieve alerts using the /JSON/alert/view/alerts/ endpoint.
    """
    zap = config.get("zap", {})
    endpoint = f"{zap.get('base_url')}/JSON/alert/view/alerts/"
    params = {}
    if zap.get("api_key"):
        params['apikey'] = zap.get("api_key")
    try:
        response = requests.get(endpoint, params=params)
        response.raise_for_status()
        print("Successfully fetched alerts from ZAP.")
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching alerts from ZAP: {e}")
        return None

def filter_alerts(alerts_data, config):
    """
    Filter alerts based on the config's "filter_risk" setting.
    Allowed values:
      - "all": include all alerts.
      - "mediumandabove": include only alerts with risk High or Medium.
      - Or a specific severity (e.g., "high", "medium", "low", "informational")
    """
    all_alerts = alerts_data.get("alerts", [])
    filter_risk = config.get("filter_risk", "High").lower()
    if filter_risk == "all":
        return all_alerts
    elif filter_risk=="high+":
        return [alert for alert in all_alerts if alert.get("risk", "").lower() == "high"]
    elif filter_risk == "medium+":
        return [alert for alert in all_alerts if alert.get("risk", "").lower() in ["high", "medium"]]
    elif filter_risk == "low+":
        return [alert for alert in all_alerts if alert.get("risk", "").lower() in ["high", "medium", "low"]]
    else:
        return [alert for alert in all_alerts if alert.get("risk", "").lower() == filter_risk]

# ============================================
# MAIN EXECUTION
# ============================================
    
def main():
    config = load_config()
    zap_data = get_zap_alerts_data(config)
    if not zap_data:
        print("No data retrieved from ZAP. Exiting.")
        return

    filtered_alerts = filter_alerts(zap_data, config)
    print(f"Number of alerts (filtered by '{config.get('filter_risk')}'): {len(filtered_alerts)}")

    mode = config.get("mode", "report").lower()
    if mode == "kb":
        markdown_output = format_kb_markdown(filtered_alerts, config)
    else:
        markdown_output = format_report_markdown(filtered_alerts, config)
    
    if config.get("dry_run", True):
        print("\n--- Markdown Output ---\n")
        print(markdown_output)
        output_file = "assessment.md" if mode == "report" else "kb_update.md"
        try:
            with open(output_file, "w") as f:
                f.write(markdown_output)
            print(f"\nMarkdown content written to {output_file}")
        except IOError as io_err:
            print(f"Error writing Markdown file: {io_err}")
    else:
        # Optionally, convert Markdown to HTML here before publishing if needed.
        html_content = markdown_output  # Conversion step could be added here.
        create_confluence_page(html_content, config)

if __name__ == "__main__":
    main()
