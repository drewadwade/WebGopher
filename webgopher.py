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
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
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
    XCTO = "**MISSING"
    RP = "**MISSING"
    PP = "**MISSING"
    STS = "**MISSING"
    BAD = 0

    try: 
        response = requests.get(URL, verify=False)
        if "Content-Security-Policy" in str(response.headers):
            CSP = response.headers['Content-Security-Policy']
        if "X-Frame-Options" in str(response.headers):
            XFO = response.headers['X-Frame-Options']
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
    
    CSP = "Content-Security-Policy: " + CSP
    XFO = "X-Frame-Options: " + XFO
    XCTO = "X-Content-Type-Options: " + XCTO
    RP = "Referrer-Policy: " + RP
    PP = "Permissions-Policy: " + PP
    STS = "Strict-Transport-Security: " + STS

    Headers = [CSP,XFO,XCTO,RP,PP,STS,BAD]
    return Headers


def getTLS(URL,driver):
   
    driver.get('https://www.cdn77.com/tls-test?domain='+URL)

    element = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CLASS_NAME, "TlsTestResultItem_title__uFAwK"))
    )
    
    tables = driver.find_elements(By.CLASS_NAME, "TlsTestResultsTable_table__3Sxyn")
 
    TLS = ""
    
    for table in tables:
        TLS += " " + (table.text).replace('\n', ' ').replace('\r', '')

    TLS = TLS.split("led")
    TLS.pop()

    return TLS


def getCert(URL):

    driver.get('https://www.sslshopper.com/ssl-checker.html#hostname='+URL)

    element = WebDriverWait(driver, 20).until(
        EC.presence_of_element_located((By.CLASS_NAME, "checker_messages"))
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

    response = requests.get(URL, verify=False, headers={'Cache-Control': 'no-cache'})

    bad_cookies = []

    for cookie in response.cookies:
        print(cookie)
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

#URLs = ['http://support.gazelle.ai']

chrome_options = Options()  
chrome_options.add_argument("--headless")  
chrome_options.binary_location = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'  
driver = webdriver.Chrome(executable_path=os.path.abspath("/Library/Frameworks/Python.framework/Versions/3.7/bin/chromedriver"), options=chrome_options)

# Output to file
#try:    
output_file=open("./reportfile.txt",'a')
for URL in URLs:
    output_file.write("###############################################\n")
    output_file.write(URL)
    output_file.write("\n###############################################\n")
    Headers = getHeaders(URL) 
    if Headers[6] == 0:
        output_file.write("---SECURITY HEADERS---\n")
        output_file.write(Headers[0])
        output_file.write("\n")
        output_file.write(Headers[1])
        output_file.write("\n")
        output_file.write(Headers[2])
        output_file.write("\n")
        output_file.write(Headers[3])
        output_file.write("\n")
        output_file.write(Headers[4])
        output_file.write("\n")
        output_file.write(Headers[5])
        output_file.write("\n\n")
        if "https" in str(URL):
            output_file.write("-- SSL/TLS VERSIONS --\n")
            TLS = getTLS(URL,driver)
            for line in TLS:
                line = line.strip()+"led\n"
                if "deprecated" in line and "enabled" in line:
                    line = "**" + line
                elif "deprecated" not in line and "disabled" in line:                   
                    line = "**" + line
                output_file.write(line)
            output_file.write("\n")
            output_file.write("---CERTIFICATE CHECK---\n")
            Cert = getCert(URL)
            output_file.write(Cert)
            output_file.write("\n\n")
        Cookies = getCookies(URL)    
        if Cookies:
            output_file.write("---COOKIE SECURITY FLAGS---\n")
            for Cookie in Cookies:
                output_file.write(Cookie)
            output_file.write("\n")
        
    else:
        output_file.write("Site not found.\n\n")
    output_file.write("\n\n")

driver.quit()
output_file.close()
print("Success! Your report has been saved to: ./reportfile.txt")
#except:     
#    print("Error: The report failed to generate. Check your input file and settings.")
#    usage()
