import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
import json

# Function to read payloads from a file
def read_payloads_from_file(file_path):
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file.readlines()]
    return payloads

# Function to inject XSS into a URL
def inject_xss_in_url(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # Update all parameters to replace their values with the payload
    for param in query_params:
        query_params[param] = [payload]
    
    modified_query = urlencode(query_params, doseq=True)
    modified_url = parsed_url._replace(query=modified_query)
    
    return urlunparse(modified_url)

# Function to test XSS in a URL using Selenium
def test_xss_with_selenium(url, payloads, results):
    driver = webdriver.Chrome()  # Ensure you have installed ChromeDriver
    for payload in payloads:
        modified_url = inject_xss_in_url(url, payload)  # Inject XSS into the URL
        
        driver.get(modified_url)
        
        try:
            # Attempt to check the type of alert (alert, confirm, prompt)
            alert = Alert(driver)
            alert_text = alert.text
            results.append({"url": modified_url, "payload": payload, "alert": alert_text})
            alert.accept()
        except:
            try:
                confirm = driver.switch_to.alert
                confirm.accept()  # If it's a confirm alert, accept it
                results.append({"url": modified_url, "payload": payload, "alert": "confirm"})
            except:
                try:
                    prompt = driver.switch_to.alert
                    prompt.send_keys('Test')  # Send text to test a prompt
                    prompt.accept()
                    results.append({"url": modified_url, "payload": payload, "alert": "prompt"})
                except:
                    results.append({"url": modified_url, "payload": payload, "alert": "No XSS detected"})
    
    driver.quit()

# Function to test XSS in a URL using requests and BeautifulSoup
def test_xss_in_url(url, payloads, results):
    for payload in payloads:
        modified_url = inject_xss_in_url(url, payload)  # Inject XSS into the URL
        
        try:
            response = requests.get(modified_url, timeout=10)
            response_text = response.text
            
            # Use BeautifulSoup to parse the response text
            soup = BeautifulSoup(response_text, 'html.parser')
            
            # Check if the payload is present in the response in multiple ways
            if payload in response.url or payload in response_text or any(payload in element for element in soup.stripped_strings):
                results.append({"url": modified_url, "payload": payload, "alert": "XSS Detected"})
            else:
                results.append({"url": modified_url, "payload": payload, "alert": "No XSS found"})
        except requests.exceptions.RequestException as e:
            results.append({"url": modified_url, "payload": payload, "alert": f"Error: {e}"})

# Function to process all URLs from a file
def process_urls_from_file(urls_file_path, payloads_file_path, use_selenium=False):
    payloads = read_payloads_from_file(payloads_file_path)
    with open(urls_file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]
    
    results = []
    
    if use_selenium:
        with ThreadPoolExecutor(max_workers=10) as executor:
            for url in urls:
                executor.submit(test_xss_with_selenium, url, payloads, results)
    else:
        with ThreadPoolExecutor(max_workers=10) as executor:
            for url in urls:
                executor.submit(test_xss_in_url, url, payloads, results)
    
    # Save the results in a JSON file
    with open('xss_results.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)
    print("Results saved to xss_results.json")

# File paths for the URLs and payloads
urls_file_path = "url.txt"  # Replace this with the name of your file containing URLs
payloads_file_path = "payloads.txt"  # Replace this with the name of your file containing payloads
use_selenium = True  # Choose whether to use Selenium or requests

# Process the URLs
process_urls_from_file(urls_file_path, payloads_file_path, use_selenium)
