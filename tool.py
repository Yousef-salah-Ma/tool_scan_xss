import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
import json
import time
import csv

def read_payloads_from_file(file_path):
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file.readlines()]
    return payloads  # Load all payloads

def inject_xss_in_url(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        query_params[param] = [payload]

    modified_query = urlencode(query_params, doseq=True)
    modified_url = parsed_url._replace(query=modified_query)

    return urlunparse(modified_url)

def test_xss_with_selenium(driver, url, payloads, results):
    for payload in payloads:
        modified_url = inject_xss_in_url(url, payload) 

        try:
            driver.get(modified_url)

           
            try:
                alert = Alert(driver)
                alert_text = alert.text
                results.append({"url": modified_url, "payload": payload, "alert": alert_text})
                alert.accept() 
                break  
            except:
                pass  

          
            script_to_check = """
            let detectedEvents = [];
            let allElements = document.querySelectorAll('*');
            allElements.forEach(element => {
                let events = ['onmouseover', 'onclick', 'onfocus', 'onblur', 'oninput', 'onchange', 'onkeydown'];
                events.forEach(event => {
                    let eventListener = element.getAttribute(event);
                    if (eventListener && eventListener.includes('alert')) {
                        detectedEvents.push(event + ': ' + eventListener);
                    }
                });
            });
            return detectedEvents;
            """
            try:
                detected_events = driver.execute_script(script_to_check)
                if detected_events:
                    results.append({"url": modified_url, "payload": payload, "events": detected_events})
            except Exception as e:
                results.append({"url": modified_url, "payload": payload, "error": str(e)})
        except Exception as e:
            results.append({"url": modified_url, "payload": payload, "error": str(e)})


def test_xss_in_url(url, payloads, results):
    for payload in payloads:
        modified_url = inject_xss_in_url(url, payload) 

        try:
            response = requests.get(modified_url, timeout=10)
            response.raise_for_status() 
            response_text = response.text

            soup = BeautifulSoup(response_text, 'html.parser')
          
            if payload in response.url or payload in response_text or any(payload in element for element in soup.stripped_strings):
                results.append({"url": modified_url, "payload": payload, "alert": "XSS Detected"})
        except requests.exceptions.Timeout:
            results.append({"url": modified_url, "payload": payload, "error": "Timeout"})
        except requests.exceptions.RequestException as e:
            results.append({"url": modified_url, "payload": payload, "error": str(e)})


def process_urls_from_file(urls_file_path, payloads_file_path, use_selenium=False, use_multithreading=True):
    payloads = read_payloads_from_file(payloads_file_path)
    with open(urls_file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]

    results = []

    if use_selenium:
        
        driver = webdriver.Chrome() 
        try:
            for url in urls:
                test_xss_with_selenium(driver, url, payloads, results)
        finally:
            driver.quit() 
    else:
        if use_multithreading:
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = []
                for url in urls:
                    futures.append(executor.submit(test_xss_in_url, url, payloads, results))

            
                for future in as_completed(futures):
                    future.result() 
        else:
          
            for url in urls:
                test_xss_in_url(url, payloads, results)

  
    with open('xss_results.json', 'w') as outfile:
        json.dump(results, outfile, indent=4)

   
    with open('xss_results.csv', 'w', newline='') as csvfile:
        fieldnames = ["url", "payload", "alert", "events", "error"] 
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

    print("Results saved to xss_results.json and xss_results.csv")


urls_file_path = "https.txt" 
payloads_file_path = "strong_xss_payloads.txt" 
use_selenium = True  
use_multithreading = True

process_urls_from_file(urls_file_path, payloads_file_path, use_selenium, use_multithreading)
