import requests
from bs4 import BeautifulSoup
import pandas as pd
import time

class CWEExtraction:
    def __init__(self):
        self.base_url = "https://cwe.mitre.org/data/definitions/"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.primary_categories = {
            'Software Development': {'Design', 'Implementation', 'Operating System', 'Configuration'},
            'Security Features': {'Authentication', 'Authorization', 'Cryptography', 'Credentials Management'},
            'Input Validation': {'Buffer Errors', 'Input Validation', 'Numeric Errors', 'Path Traversal'},
            'Resource Management': {'Memory Management', 'Resource Management', 'File Handling'},
            'Code Quality': {'Error Handling', 'Information Leak', 'Race Conditions'},
            'Web Security': {'XSS', 'SQL Injection', 'CSRF', 'Session Management'}
        }

    def get_page_content(self, cwe_id: int) -> str:
        """Fetch the HTML content for a given CWE ID."""
        url = f"{self.base_url}{cwe_id}.html"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.text
        except requests.RequestException as e:
            print(f"Error fetching CWE-{cwe_id}: {e}")
        return ""

    def parse_cwe_page(self, html_content: str) -> dict:
        """Extract Description and Exploitability."""
        if not html_content:
            return {}
        
        soup = BeautifulSoup(html_content, 'html.parser')
        data = {}
        
        # Extract Description
        desc_div = soup.find('div', {'id': 'Description'})
        if desc_div:
            desc_content = desc_div.find_next('div', {'class': 'detail'})
            data['Description'] = desc_content.get_text(strip=True) if desc_content else ""
        
        # Extract Exploitability
        exploit_div = soup.find('div', {'id': 'Likelihood_Of_Exploit'})
        if exploit_div:
            exploit_content = exploit_div.find_next('div', {'class': 'detail'})
            data['Exploitability'] = exploit_content.get_text(strip=True) if exploit_content else "Not Specified"
        else:
            data['Exploitability'] = "Not Specified"
            
        return data

    def determine_category(self, text: str) -> str:
        """Determine the category based on description text."""
        text = text.lower()
        
        for category, keywords in self.primary_categories.items():
            for keyword in keywords:
                if keyword.lower() in text:
                    return category
        return "Other"

    def scrape_all_cwes(self, start_id: int = 1, end_id: int = 1400) -> pd.DataFrame:
        """Scrape all CWEs."""
        all_data = []
        successful = 0
        
        for cwe_id in range(start_id, end_id + 1):
            print(f"Scraping CWE-{cwe_id}...")
            
            html_content = self.get_page_content(cwe_id)
            if html_content:
                data = self.parse_cwe_page(html_content)
                if data and 'Description' in data:
                    data['CWE_ID'] = cwe_id
                    data['Category'] = self.determine_category(data['Description'])
                    all_data.append(data)
                    successful += 1
            
            # Be nice to the server
            time.sleep(1)
        
        df = pd.DataFrame(all_data)
        if not df.empty:
            df = df[['CWE_ID', 'Description', 'Exploitability', 'Category']]
        
        print(f"\nTotal CWEs collected: {successful}")
        print("\nCategory Distribution:")
        if not df.empty:
            print(df['Category'].value_counts())
        
        return df

def main():
    scraper = CWEExtraction
    
    ()
    
    # Scrape all CWEs
    df = scraper.scrape_all_cwes()
    
    # Save to CSV
    df.to_csv('cwe_full_dataset.csv', index=False)
    print("\nData saved to cwe_full_dataset.csv")

if __name__ == "__main__":
    main()