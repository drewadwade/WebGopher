#!/usr/bin/python3
# -*- encryption: utf-8 -*-
"""
Created on Sun 29 Nov 2020
@author: Andrew Wade 

WebGopher
Because we like to collect this information in a web application assessment 
but no one wants to do it...this tool fetches standard web assessment 
information for a list of URLs provided in an input file. The input file must 
contain one URL per line and the URLs must include their protocol (http or https).

REQUIRES: ChromeDriver - https://sites.google.com/a/chromium.org/chromedriver/downloads
          Add to PATH and update driver variable

***Usage***
python3 webgopher.py <inputfile>
"""

# Include standard modules
import os
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


# Define the usage message for display on failed attempts and exit the program
def usage():
    print("")
    print("usage: python3 webgopher.py <inputfile>")
    print("WebGopher fetches basic web assessment info")
    print("")
    print("positional arguments:")
    print("  inputfile                provide the filename of the file with the URLs")
    print("                           input file must have one URL per line")
    print("                           URL must include protocol (http/https)")
    print("")
    exit()

def getHeaders(URL):

    CSP = "**MISSING"
    XFO = "**MISSING"
    XSS = "**MISSING"
    XCTO = "**MISSING"
    RP = "**MISSING"
    PP = "**MISSING"
    STS = "**MISSING"
    BAD = 0

    try: 
        response = requests.head(URL, verify=False)
        if "Content-Security-Policy" in str(response.headers):
            CSP = response.headers['Content-Security-Policy']
        if "X-Frame-Options" in str(response.headers):
            XFO = response.headers['X-Frame-Options']
        if "X-XSS-Protection" in str(response.headers):
            XSS = response.headers['X-XSS-Protection']
        if "X-Content-Type-Options" in str(response.headers):
            XCTO = response.headers['X-Content-Type-Options']
        if "Referrer-Policy" in str(response.headers):
            RP = response.headers['Referrer-Policy']
        if "Permissions-Policy" in str(response.headers):
            PP = response.headers['Permissions-Policy']
        if "Strict-Transport-Security" in str(response.headers):
            STS = response.headers['Strict-Transport-Security']
    except:
        BAD = 1
       
    Headers = [URL,CSP,XFO,XSS,XCTO,RP,PP,STS,BAD]
    return Headers


def getTLS(URL,driver):
   
    driver.get('https://www.cdn77.com/tls-test?domain='+URL)

    element = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CLASS_NAME, "TlsTestResultItem_title__uFAwK"))
    )
    
    tables = driver.find_elements(By.CLASS_NAME, "TlsTestResultsTable_table__3Sxyn")
 
    TLS = ""
    
    for table in tables:
        TLS += URL + "led " + (table.text).replace('\n', ' ').replace('\r', '')

    TLS = TLS.split("led")
    TLS.pop()

    return TLS


def getCert(URL):

    driver.get('https://www.sslshopper.com/ssl-checker.html?hostname='+URL)

    element = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CLASS_NAME, "checker_certs"))
    )

    try:
        failed = driver.find_element(By.CLASS_NAME, "failed")
        if failed:
            table = driver.find_element(By.CLASS_NAME, "checker_messages")
            Cert = table.text
    except: 
        Cert = "Certificate OK"
    
    return Cert


def getCookies(URL):
    Secure = "**MISSING Secure flag"
    HTTPOnly = "**MISSING HTTP Only flag"

    response = requests.get(URL, verify=False)

    bad_cookies = []
    
    for cookie in response.cookies:
        if cookie.secure: 
            Secure = " "                  #Secure flag OK
        if cookie.has_nonstandard_attr('HttpOnly'):
            HTTPOnly = " "                #HTTPOnly flag OK
        if ((Secure != " ") or (HTTPOnly != " ")):
            bad_cookie = (cookie.name).strip("\n") + ": " + Secure.strip("\n") + " " + HTTPOnly.strip("\n") + "\n"
            bad_cookies += bad_cookie

    return bad_cookies



# Check for input file
try:
    inputfile=open(sys.argv[1])
    getURLs=inputfile.read()
    inputfile.close()
except:
    print("Error: Input file could not be accessed.")
    usage()

URLs = getURLs.split("\n")

chrome_options = Options()  
chrome_options.add_argument("--headless")  
chrome_options.binary_location = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'  
driver = webdriver.Chrome(executable_path=os.path.abspath("/Library/Frameworks/Python.framework/Versions/3.7/bin/chromedriver"), options=chrome_options)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Output to file
try:    
    output_file=open("./reportfile.txt",'a')
    
    
    output_file.write("---SITES NOT FOUND---\n")
    
    Headers = []
    liveURLs = []
    empty = 1
    
    for URL in URLs:
        SiteHeaders = getHeaders(URL) 
        if SiteHeaders[8] == 0:
            Headers += [SiteHeaders]
            empty = 0
            liveURLs += [URL]
        else:
            output_file.write("  ")
            output_file.write(URL)
            output_file.write("\n")
    
    if empty == 1:
         output_file.write("none\n")
    
    output_file.write("\n")
                
    output_file.write("---MISSING SECURITY HEADERS---\n")
    
    sec_headers = ["Content-Security-Policy:","X-Frame-Options:","X-XSS-Protection:","X-Content-Type-Options:","Referrer-Policy:","Permissions-Policy:","Strict-Transport-Security:"]
    
    for sec_header in sec_headers:
        title = "Missing " + sec_header
        output_file.write(title)
        output_file.write("\n")
        for item in range(0,len(Headers)):
            if Headers[item][8] == 0: 
                if "**MISSING" in Headers[item][sec_headers.index(sec_header)+1]:
                    output_file.write("  ")
                    output_file.write(Headers[item][0])
                    output_file.write("\n")
        output_file.write("\n")
    
    output_file.write("---UNSAFE SSL/TLS VERSIONS---\n")
    
    TLS_versions = ["TLS 1.3 Disabled","TLS 1.2 Disabled","TLS 1.1 Enabled","TLS 1.0 Enabled","SSLv3 Enabled","SSLv2 Enabled"]
    TLS_results = []
    
    for URL in liveURLs:
        if "https" in str(URL):
            TLS = getTLS(URL,driver)
            TLS_results += [TLS]
        
    for TLS_version in TLS_versions:
        output_file.write(TLS_version)
        output_file.write("\n")
        
        for item in range(0,len(TLS_results)):
            result = TLS_results[item][TLS_versions.index(TLS_version)+1]
            if "deprecated" in result and "enab" in result:
                output_file.write("  ")
                output_file.write(TLS_results[item][0])
                output_file.write("\n")
            elif "deprecated" not in result and "disab" in result:                   
                output_file.write("  ")
                output_file.write(TLS_results[item][0])
                output_file.write("\n")
        output_file.write("\n")
                
            
    output_file.write("---CERTIFICATE ISSUES---\n")
    
    for URL in liveURLs:
        if "https" in str(URL):
            CertIssue = getCert(URL)
            if "Certificate OK" not in CertIssue:
                output_file.write(URL)
                output_file.write("\n")
    
    output_file.write("\n")
    
    output_file.write("---MISSING COOKIE SECURITY FLAGS---\n")
    for URL in liveURLs:
        Cookies = getCookies(URL)    
        if Cookies:
            output_file.write(URL)
            output_file.write("\n")
            for Cookie in Cookies:
                output_file.write(Cookie)
            output_file.write("\n")
        
    driver.close()
    output_file.close()
    print("Success! Your report has been saved to: ./reportfile.txt")
except:     
    print("Error: The report failed to generate. Check your input file and settings.")
    usage()
