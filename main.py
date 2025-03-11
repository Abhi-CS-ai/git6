
import time
import os
import json
import base64
import requests
import threading
from datetime import datetime, timedelta
import webbrowser
import msal  # Microsoft Authentication Library

class OutlookEmailScanner:
    def __init__(self):
        # Microsoft Graph API settings
        self.client_id = None  # To be set by user
        self.tenant_id = None  # To be set by user
        self.redirect_uri = "http://localhost:8000"
        self.scopes = ["Mail.Read"]
        
        # VirusTotal API settings
        self.vt_api_key = None  # To be set by user
        self.vt_url_scan = "https://www.virustotal.com/api/v3/urls"
        self.vt_file_scan = "https://www.virustotal.com/api/v3/files"
        
        # Email scanning settings
        self.scan_interval = 60  # seconds
        self.last_scan_time = datetime.now() - timedelta(hours=1)
        
        # Authentication tokens
        self.access_token = None
        self.refresh_token = None
        
        # Thread control
        self.running = False
        self.scan_thread = None
        
        # Scanning stats
        self.scanned_emails = 0
        self.threats_detected = 0
        
        print("Email Scanner initialized. Waiting for configuration...")

    def authenticate_microsoft(self):
        """Authenticate with Microsoft Graph API"""
        if not self.client_id or not self.tenant_id:
            print("Microsoft credentials not configured.")
            return False
            
        # Create MSAL app
        app = msal.PublicClientApplication(
            client_id=self.client_id,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}"
        )
        
        # Initiate device flow
        flow = app.initiate_device_flow(scopes=self.scopes)
        print(flow['message'])
        
        # Poll for token
        result = app.acquire_token_by_device_flow(flow)
        
        if "access_token" in result:
            self.access_token = result["access_token"]
            print("Authentication successful.")
            return True
        else:
            print(f"Authentication failed: {result.get('error')}")
            return False

    def get_recent_emails(self):
        """Fetch recent unread emails from Outlook"""
        if not self.access_token:
            print("Not authenticated. Cannot fetch emails.")
            return []
            
        # Set time filter to only get emails since last scan
        time_filter = self.last_scan_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Endpoint to get recent messages
        endpoint = "https://graph.microsoft.com/v1.0/me/messages"
        params = {
            "$filter": f"receivedDateTime ge {time_filter} and isRead eq false",
            "$select": "id,subject,receivedDateTime,bodyPreview,hasAttachments"
        }
        
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(endpoint, headers=headers, params=params)
            response.raise_for_status()
            emails = response.json().get("value", [])
            self.last_scan_time = datetime.now()
            return emails
        except requests.exceptions.RequestException as e:
            print(f"Error fetching emails: {e}")
            return []

    def get_email_attachments(self, email_id):
        """Fetch attachments for a specific email"""
        if not self.access_token:
            return []
            
        endpoint = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}/attachments"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            return response.json().get("value", [])
        except requests.exceptions.RequestException as e:
            print(f"Error fetching attachments: {e}")
            return []

    def extract_urls_from_email(self, email_id):
        """Extract URLs from email body"""
        if not self.access_token:
            return []
            
        endpoint = f"https://graph.microsoft.com/v1.0/me/messages/{email_id}/body"
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            
            # Simple URL extraction - in a real app, use more sophisticated regex
            body = response.json().get("content", "")
            urls = []
            
            # Very basic URL extraction - a more robust solution would use regex
            if "http://" in body or "https://" in body:
                words = body.split()
                for word in words:
                    if word.startswith("http://") or word.startswith("https://"):
                        urls.append(word)
            
            return urls
        except requests.exceptions.RequestException as e:
            print(f"Error extracting URLs: {e}")
            return []

    def scan_url_with_virustotal(self, url):
        """Scan a URL with VirusTotal API"""
        if not self.vt_api_key:
            print("VirusTotal API key not configured.")
            return None
            
        headers = {
            "x-apikey": self.vt_api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        data = {"url": url}
        
        try:
            # Submit URL for analysis
            response = requests.post(self.vt_url_scan, headers=headers, data=data)
            response.raise_for_status()
            
            # Get analysis ID
            analysis_id = response.json().get("data", {}).get("id")
            
            if not analysis_id:
                return None
                
            # Wait for analysis to complete (respect rate limits)
            time.sleep(15)  # Free API has rate limits
            
            # Get analysis results
            result_url = f"{self.vt_url_scan}/{analysis_id}"
            result_response = requests.get(result_url, headers=headers)
            result_response.raise_for_status()
            
            return result_response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error scanning URL: {e}")
            return None

    def scan_file_with_virustotal(self, file_content, file_name):
        """Scan a file with VirusTotal API"""
        if not self.vt_api_key:
            print("VirusTotal API key not configured.")
            return None
            
        headers = {
            "x-apikey": self.vt_api_key
        }
        
        try:
            # Get upload URL
            upload_url_response = requests.get(
                "https://www.virustotal.com/api/v3/files/upload_url", 
                headers=headers
            )
            upload_url_response.raise_for_status()
            upload_url = upload_url_response.json().get("data")
            
            # Upload file
            files = {"file": (file_name, file_content)}
            upload_response = requests.post(upload_url, headers=headers, files=files)
            upload_response.raise_for_status()
            
            # Get analysis ID
            analysis_id = upload_response.json().get("data", {}).get("id")
            
            if not analysis_id:
                return None
                
            # Wait for analysis to complete (respect rate limits)
            time.sleep(15)  # Free API has rate limits
            
            # Get analysis results
            result_url = f"{self.vt_file_scan}/{analysis_id}"
            result_response = requests.get(result_url, headers=headers)
            result_response.raise_for_status()
            
            return result_response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error scanning file: {e}")
            return None

    def analyze_email_security(self, email):
        """Analyze an email for security threats"""
        email_id = email.get("id")
        threats = []
        
        # 1. Extract and scan URLs
        urls = self.extract_urls_from_email(email_id)
        for url in urls[:3]:  # Limit due to API rate limits
            result = self.scan_url_with_virustotal(url)
            if result:
                stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                if stats.get("malicious", 0) > 0:
                    threats.append({
                        "type": "malicious_url",
                        "url": url,
                        "detection_count": stats.get("malicious", 0)
                    })
                    
        # 2. Scan attachments if present
        if email.get("hasAttachments"):
            attachments = self.get_email_attachments(email_id)
            for attachment in attachments[:1]:  # Limit due to API rate limits
                content = base64.b64decode(attachment.get("contentBytes", ""))
                name = attachment.get("name", "unknown_file")
                
                result = self.scan_file_with_virustotal(content, name)
                if result:
                    stats = result.get("data", {}).get("attributes", {}).get("stats", {})
                    if stats.get("malicious", 0) > 0:
                        threats.append({
                            "type": "malicious_attachment",
                            "filename": name,
                            "detection_count": stats.get("malicious", 0)
                        })
        
        # 3. Basic phishing indicators (very simple check - would be more sophisticated in real app)
        subject = email.get("subject", "").lower()
        body_preview = email.get("bodyPreview", "").lower()
        
        phishing_keywords = [
            "urgent", "account suspended", "verify your account", "password reset",
            "unusual activity", "login attempt", "security alert"
        ]
        
        keyword_matches = []
        for keyword in phishing_keywords:
            if keyword in subject or keyword in body_preview:
                keyword_matches.append(keyword)
                
        if keyword_matches:
            threats.append({
                "type": "potential_phishing",
                "indicators": keyword_matches
            })
            
        return threats

    def notify_user(self, email, threats):
        """Notify user about potential threats"""
        if not threats:
            return
            
        print("\n" + "=" * 50)
        print(f"⚠️ SECURITY ALERT: Potential threats detected in email")
        print(f"Subject: {email.get('subject')}")
        print(f"Received: {email.get('receivedDateTime')}")
        print("Detected threats:")
        
        for threat in threats:
            if threat["type"] == "malicious_url":
                print(f"  - Malicious URL detected: {threat['url']}")
                print(f"    Detection count: {threat['detection_count']}")
            elif threat["type"] == "malicious_attachment":
                print(f"  - Malicious attachment detected: {threat['filename']}")
                print(f"    Detection count: {threat['detection_count']}")
            elif threat["type"] == "potential_phishing":
                print(f"  - Potential phishing email detected")
                print(f"    Indicators: {', '.join(threat['indicators'])}")
                
        print("=" * 50 + "\n")
        self.threats_detected += 1

    def scan_emails(self):
        """Scan emails for threats"""
        print(f"Scanning for new emails since {self.last_scan_time}...")
        
        emails = self.get_recent_emails()
        if not emails:
            print("No new emails found.")
            return
            
        print(f"Found {len(emails)} new emails to scan.")
        
        for email in emails:
            print(f"Scanning email: {email.get('subject')}")
            self.scanned_emails += 1
            
            # Analyze email for security threats
            threats = self.analyze_email_security(email)
            
            # Notify user if threats found
            if threats:
                self.notify_user(email, threats)
            else:
                print(f"No threats detected in email: {email.get('subject')}")
                
            # Respect API rate limits (4 requests per minute for free tier)
            time.sleep(15)

    def scanning_thread(self):
        """Thread function for continuous scanning"""
        while self.running:
            try:
                # Check if authenticated
                if not self.access_token:
                    print("Not authenticated. Attempting to authenticate...")
                    if not self.authenticate_microsoft():
                        print("Authentication failed. Retrying in 60 seconds...")
                        time.sleep(60)
                        continue
                
                # Scan emails
                self.scan_emails()
                
                # Display statistics
                print(f"\nScanning statistics:")
                print(f"Emails scanned: {self.scanned_emails}")
                print(f"Threats detected: {self.threats_detected}")
                
                # Wait for next scan interval
                print(f"Waiting {self.scan_interval} seconds until next scan...")
                time.sleep(self.scan_interval)
                
            except Exception as e:
                print(f"Error in scanning thread: {e}")
                time.sleep(60)  # Wait before retrying

    def start_scanning(self):
        """Start the email scanning service"""
        if self.running:
            print("Scanning is already running.")
            return
            
        print("Starting email scanning service...")
        self.running = True
        self.scan_thread = threading.Thread(target=self.scanning_thread)
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def stop_scanning(self):
        """Stop the email scanning service"""
        if not self.running:
            print("Scanning is not running.")
            return
            
        print("Stopping email scanning service...")
        self.running = False
        if self.scan_thread:
            self.scan_thread.join(timeout=5)
        
    def configure(self):
        """Configure the scanner with user input"""
        print("\n=== Email Scanner Configuration ===")
        
        # Microsoft Graph API credentials
        self.client_id = input("Enter Microsoft Azure App Client ID: ").strip()
        self.tenant_id = input("Enter Microsoft Azure Tenant ID: ").strip()
        
        # VirusTotal API key
        self.vt_api_key = input("Enter VirusTotal API Key: ").strip()
        
        # Scan interval
        interval = input("Enter scan interval in seconds (default 60): ").strip()
        if interval and interval.isdigit():
            self.scan_interval = int(interval)
            
        print("\nConfiguration complete.")
        print("You will now be prompted to authenticate with Microsoft...")

def main():
    print("Starting Outlook Email Security Scanner")
    print("This application scans your Outlook emails for potential security threats")
    
    scanner = OutlookEmailScanner()
    scanner.configure()
    
    if scanner.authenticate_microsoft():
        scanner.start_scanning()
        
        print("\nEmail scanner is running in the background.")
        print("Press Ctrl+C to stop the scanner.")
        
        try:
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping scanner...")
            scanner.stop_scanning()
            print("Scanner stopped. Goodbye!")
    else:
        print("Failed to authenticate. Please restart the application and try again.")

if __name__ == "__main__":
    main()
