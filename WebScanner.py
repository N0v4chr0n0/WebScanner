#--------------------------------Requierements----------------------------------
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import time
import re
import pyfiglet
from colorama import Fore, init
from pdf_reporter import PentestReporter

#-------------------------------------Header------------------------------------

text = "WebScanner"
ascii_art_text = pyfiglet.figlet_format(text, font='big')
print("------------------------------------------------------------------------")
print(Fore.BLUE + ascii_art_text + Fore.RESET)
print("------------------------------------------------------------------------")
print("By" + Fore.BLUE + " N0v4chr0n0" + Fore.RESET)
print("Github : " + Fore.BLUE + "https://github.com/N0v4chr0n0/WebScanner" + Fore.RESET)
print("------------------------------------------------------------------------")

#-------------------------------------URL---------------------------------------
url = input(Fore.RED + "[•] Enter your url: " + Fore.RESET)
i=1
while i==1 :
    print("[?] Is This your correct url ", Fore.GREEN + url + Fore.RESET)
    answer = input("[?] (y/n) ")
    if answer == "y" :
        i=0
    else :
        url = input(Fore.RED + "[•] Enter your correct url: " + Fore.RESET)

#------------------------------Connection-------------------------------------

session = requests.Session()
session.headers["User-Agent"] = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.1.2 Safari/605.1.15"
)

#-----------------------------------Time management---------------------------------------
def format_time(seconds):
    minutes = seconds // 60
    remaining_seconds = seconds % 60
    return f"{int(minutes)} minutes and {int(remaining_seconds)} seconds"

#------------------------------Retrieve forms and details---------------------------------

def retrieve_all_forms(url):
    soup = bs(session.get(url).content, "html.parser")
    return soup.find_all("form")

def retrieve_form_details(form):
    details = {}
    # Retrieve the target URL of the form action
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # Retrieve the form method
    method = form.attrs.get("method", "get").lower()
    # Retrieve details of all input elements including their types and names
    inputs = []
    for input_tag in form.find_all("input"):
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        input_type = input_tag.attrs.get("type", "text")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # Store all extracted details into the resulting dictionary
    details["method"] = method
    details["inputs"] = inputs
    details["action"] = action
    
    return details

def retrieve_form(form_details, url, value): 
    
    target_url = urljoin(url, form_details["action"])

    # Retrieve the inputs
    inputs = form_details["inputs"]
    data = {}

    for input in inputs:
        # Substitute all text and search values with the specified value
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # Include inputs with both name and value
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

#------------------------------Scan fonctions---------------------------------

def XSS_Scan(url):
    global total_time
    xss_result = []
    start_time = time.time()  # Start the timer
    print(Fore.LIGHTBLUE_EX + "[•] Running XSS Scan on", url)
    
    try:
        #prepare the payloads
        f = open('XSS_Payload.txt', encoding="utf8")
        payloads = f.read().splitlines()
        
        # Fetch all forms from the provided URL
        forms = retrieve_all_forms(url)
        if not forms:
            # Return if no forms found
            print(Fore.RED + f"[•] No forms found on {url}")

        print(Fore.LIGHTGREEN_EX + "[e] Identified ", end="")
        print(f"{len(forms)} forms on {url}.")

        # Iterate through all forms and payloads
        for form in forms:
            form_details = retrieve_form_details(form)
            for payload in payloads:
                content = retrieve_form(form_details, url, payload).content.decode()

                # Check if payload triggers vulnerability
                if payload in content:
                    print(Fore.GREEN + f"[!] XSS Identified on {url}")
                    xss_result.append({
                        'form_action': form_details["action"],           
                        'method': form_details["method"],                   
                        'payload': payload,         
                    })
                    break

    except Exception as e:
        print(Fore.RED + "[•] An error occurred while scanning the URL: ", e)
    finally:
        # Stop the timer
        end_time = time.time()

        # Calculate the duration
        duration = end_time - start_time
        total_time+=duration
        # Display the completion time
        if duration > 60:
            duration_str = format_time(duration)
            print(Fore.GREEN + f"XSS Scan completed in {duration_str}." + Fore.RESET)
        else:
            print(Fore.GREEN + f"XSS Scan completed in {duration:.2f} seconds." + Fore.RESET)
    return xss_result
def SQLI_Scan(URL):
    
    # An elementary boolean function assessing whether a webpage is susceptible to SQL Injection based on its content
    def has_vulnerability(content):
        errors = {
            # SQL Server
            "unclosed quotation mark after the character string",
            # Oracle
            "quoted string not properly terminated",
            # MySQL
            "you have an error in your sql syntax;",
            "warning: mysql",
            # Postgres
            "syntax error at or near",
            "pgsql_query",
            # SQLite
            "syntax error",
            "sqlite3",
        }

        for error in errors:
            # Error detection flag, Error
            if error in content.content.decode().lower():
                return True
        # Validation successful, No error
        return False
    
    global total_time
    sqli_result = []
    start_time = time.time()  # Start the timer
    print(Fore.LIGHTBLUE_EX + "[•] Running SQLI Scan on", URL)
    
    try:
        #prepare the payloads
        f = open('SQLI_Payload.txt', 'r')
        payloads = f.read().splitlines()
        
        # Fetch all forms from the provided URL
        forms = retrieve_all_forms(URL)
        if not forms:
            # Return to main function if URL couldn't be read
            print(Fore.RED + f"[•] No forms found on {URL}.")
            
        print(Fore.LIGHTGREEN_EX + "[e] Identified ", end="")
        print(f"{len(forms)} forms on {URL}.")

        for form in forms:
            form_details = retrieve_form_details(form)
            for j in payloads:
                # Data body to be submitted
                data = {}
                for input_tag in form_details["inputs"]:
                    if input_tag['value'] or input_tag['type'] == 'hidden':
                        # Use any input from with a value or hidden attribute in the form body
                        try:
                            data[input_tag['name']] = input_tag['value'] + j
                        except:
                            pass
                    elif input_tag['type'] != 'submit':
                        # For all other actions besides submitting,
                        # utilize miscellaneous information with special characters
                        data[input_tag['name']] = f"test{j}"

                # Combine the URL with the action to form the request URL
                target_url = urljoin(URL, form_details["action"])
                if form_details['method'] == 'post':
                    res = session.post(target_url, data=data)
                elif form_details["method"] == 'get':
                    res = session.get(target_url, params=data)

                # Test to determine if the resulting page is susceptible to vulnerabilities
                if has_vulnerability(res):
                    print(Fore.GREEN + "[!] SQL Injection vulnerability detected, link:", target_url)
                    sqli_result.append({
                        'form_action': form_details["action"],          
                        'method': form_details["method"],                      
                        'payload': j,         
                    })
                    break

    except Exception as e:
        print(Fore.RED + f"[•] An error occurred while scanning the URL {URL}", e)

    # Stop the timer
    end_time = time.time()

    # Calculate the duration
    duration = end_time - start_time
    total_time+=duration
    # Check if duration exceeds 60 seconds
    if duration >= 60:
        duration_str = format_time(duration)
        print(Fore.GREEN + f"SQL Injection Scan completed in {duration_str} min." + Fore.RESET)
    else:
        print(Fore.GREEN + f"SQL Injection Scan completed in {duration:.2f} seconds." + Fore.RESET)
    return sqli_result

def CSRF_Scan(url):
    global total_time
    csrf_result = []
    start_time = time.time()  # Start the timer
    print(Fore.LIGHTBLUE_EX + "[•] Running CSRF Scan on ", url)
    
    try:
        
        # Fetch all forms from the provided URL
        forms = retrieve_all_forms(url)
        if not forms:
            # Return if no forms found
            print(Fore.RED + f"[•] No forms found on {url}")

        print(Fore.LIGHTGREEN_EX + "[e] Identified ", end="")
        print(f"{len(forms)} forms on {url}.")

        csrf_keywords = ["csrf", "token", "xsrf", "nonce", "authenticity", "anticsrf", "requestverificationtoken", "csrfmiddlewaretoken"]
        # Iterate through all forms
        for form in forms:
            form_details = retrieve_form_details(form)
            has_csrf_protection = False
            for input in form_details["inputs"] :
                if input["type"] == "hidden" :
                    field_name = input["name"].lower() if input["name"] else ""
                    if any(keyword in field_name for keyword in csrf_keywords):
                        has_csrf_protection = True
                        
            if not has_csrf_protection :
                print(Fore.GREEN + f"[!] CSRF vulnerability detected on {url}")
                csrf_result.append({
                'form_action': form_details["action"],
                'method': form_details["method"],
            })

    except Exception as e:
        print(Fore.RED + "[•] An error occurred while scanning the URL: ", e)
    finally:
        # Stop the timer
        end_time = time.time()

        # Calculate the duration
        duration = end_time - start_time
        total_time+=duration
        # Display the completion time
        if duration > 60:
            duration_str = format_time(duration)
            print(Fore.GREEN + f"CSRF Scan completed in {duration_str}." + Fore.RESET)
        else:
            print(Fore.GREEN + f"CSRF Scan completed in {duration:.2f} seconds." + Fore.RESET)
        
    return csrf_result
 
def PII_Scan(url):
    """Check for exposed sensitive information"""
    sensitive_patterns = {
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'api_key': r'api[_-]?key[_-]?([\'"|`])([a-zA-Z0-9]{32,45})\1'
    }
    pii_result = []
    global total_time
    start_time = time.time()  # Start the timer
    print(Fore.LIGHTBLUE_EX + "[•] Running PII Scan on", url)

    try:
        response = session.get(url)

        for info_type, pattern in sensitive_patterns.items():
            matches = re.finditer(pattern, response.text.lower(), re.IGNORECASE)
            if not matches:
                print(Fore.RED + f"[•] Unable to find PII in {url}")
            else :
                for match in matches:
                    pii_result.append({
                        'type': info_type,                       
                        'value': match.group(),             
                    })

    except Exception as e:
        print(Fore.RED + f"[•] Error checking sensitive information on {url}")
    finally:
        # Stop the timer
        end_time = time.time()

        # Calculate the duration
        duration = end_time - start_time
        total_time+=duration
        # Display the completion time
        if duration > 60:
            duration_str = format_time(duration)
            print(Fore.GREEN + f"PII Scan completed in {duration_str}." + Fore.RESET)
        else:
            print(Fore.GREEN + f"PII Scan completed in {duration:.2f} seconds." + Fore.RESET)
    return pii_result

#-------------------------Generating repport function---------------------------

def Gen_repport(url, sqli_results, xss_results, csrf_results, pii_results):
    # Initialize reporter
    reporter = PentestReporter(url)
    for result in sqli_results:
        reporter.add_sqli_finding(result['form_action'], result['method'], result['payload']) 
    for result in xss_results:
        reporter.add_xss_finding(result['form_action'], result['method'], result['payload'])
    for result in csrf_results:
        reporter.add_csrf_finding(result['form_action'], result['method'])
    for result in pii_results:
        reporter.add_pii_finding(result['type'], result['value'])

    # Generate the report
    reporter.create_report()

#------------------------------------main-------------------------------------

total_time = 0
scan_results = []
print("------------------------------------------------------------------------")
print("[•] Chose your Scan Scope :")
print(Fore.RED + "[1]" + Fore.GREEN + " XSS")
print(Fore.RED + "[2]" + Fore.GREEN + " SQLI")
print(Fore.RED + "[3]" + Fore.GREEN + " CSRF")
print(Fore.RED + "[4]" + Fore.GREEN + " PII")
print(Fore.RED + "[5]" + Fore.GREEN + " ALL")
choice = input (Fore.RESET + "[?] What is your Choice : ")
if choice == "1" :
    a = XSS_Scan(url)
elif choice == "2" :
    a = SQLI_Scan(url)
elif choice == "3" :
    a = CSRF_Scan(url)
elif choice == "4" :
    a = PII_Scan(url)
elif choice == "5" :
    xss_results = XSS_Scan(url)
    sqli_results = SQLI_Scan(url)
    csrf_results = CSRF_Scan(url)
    pii_results = PII_Scan(url)
    
    if total_time >= 60:
        total_time_str = format_time(total_time)
        print(Fore.GREEN + f"Scan completed in {total_time_str} min." + Fore.RESET)
    else:
        print(Fore.GREEN + f"Scan completed in {total_time:.2f} seconds." + Fore.RESET)
    print(Fore.RESET + "------------------------------------------------------------------------")
    print(Fore.RED + "[•] Generating Repport...")
    Gen_repport(url, sqli_results, xss_results, csrf_results, pii_results)










