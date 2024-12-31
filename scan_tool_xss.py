import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import aiohttp
import asyncio
import time
import json
import csv
import matplotlib.pyplot as plt
import numpy as np
from selenium import webdriver
from selenium.webdriver.common.alert import Alert
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def read_payloads_from_file(file_path):
    with open(file_path, 'r') as file:
        payloads = [line.strip() for line in file.readlines()]
    return payloads


def inject_xss_in_url(url, payload):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    for param in query_params:
        query_params[param] = [payload]
    modified_query = urlencode(query_params, doseq=True)
    modified_url = parsed_url._replace(query=modified_query)
    return urlunparse(modified_url)

async def test_xss_with_aiohttp(url, payloads, session, results, use_post=False, headers=None, cookies=None):
    for payload in payloads:
        modified_url = inject_xss_in_url(url, payload)
        start_time = time.time()

        try:
            if use_post:
              
                post_data = {"input_field": payload} 
                async with session.post(modified_url, data=post_data, headers=headers, cookies=cookies, timeout=10) as response:
                    response_text = await response.text()

                    if payload in response.url or payload in response_text:
                        results.append({"url": modified_url, "payload": payload, "alert": "XSS Detected via POST"})
            else:
                async with session.get(modified_url, headers=headers, cookies=cookies, timeout=10) as response:
                    response_text = await response.text()

                    if payload in response.url or payload in response_text:
                        results.append({"url": modified_url, "payload": payload, "alert": "XSS Detected via GET"})

        except asyncio.TimeoutError:
            results.append({"url": modified_url, "payload": payload, "error": "Timeout"})
        except Exception as e:
            results.append({"url": modified_url, "payload": payload, "error": str(e)})

        end_time = time.time()
        print(f"Time taken for {modified_url} with payload {payload}: {end_time - start_time:.2f} seconds")

async def process_urls_from_file(urls_file_path, payloads_file_path, use_selenium=False, use_post=False, headers=None, cookies=None):
    payloads = read_payloads_from_file(payloads_file_path)
    with open(urls_file_path, 'r') as file:
        urls = [line.strip() for line in file.readlines()]

    results = []
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            tasks.append(test_xss_with_aiohttp(url, payloads, session, results, use_post, headers, cookies))

        # Run all tasks concurrently
        await asyncio.gather(*tasks)

    # Save results to JSON and CSV
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open('xss_results.json', 'w') as outfile:
        json.dump({"timestamp": timestamp, "results": results}, outfile, indent=4)

    with open('xss_results.csv', 'w', newline='') as csvfile:
        fieldnames = ["url", "payload", "alert", "error", "timestamp"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            result['timestamp'] = timestamp
            writer.writerow(result)

    print(f"Results saved to xss_results.json and xss_results.csv with timestamp {timestamp}")

    
    generate_report(results)

def generate_report(results):

    xss_detected = sum(1 for result in results if result.get("alert") == "XSS Detected via GET" or result.get("alert") == "XSS Detected via POST")
    xss_not_detected = len(results) - xss_detected


    labels = ['XSS Detected', 'XSS Not Detected']
    counts = [xss_detected, xss_not_detected]
    plt.bar(labels, counts, color=['red', 'green'])
    plt.title('XSS Detection Report')
    plt.xlabel('XSS Status')
    plt.ylabel('Count')
    plt.savefig('xss_report.png')
    plt.show()


urls_file_path = "urls.txt"
payloads_file_path = "strong_xss_payloads.txt"
use_selenium = False
use_post = False  
headers = {"User-Agent": "Mozilla/5.0"}
cookies = {"session_id": "dummy_session_value"} 


asyncio.run(process_urls_from_file(urls_file_path, payloads_file_path, use_selenium, use_post, headers, cookies))
