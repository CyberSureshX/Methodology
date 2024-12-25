## Bug Bounty Methodology

**Dorking Search Engine**
- https://freelancermijan.github.io/reconengine/
- https://taksec.github.io/google-dorks-bug-bounty/
- https://dorks.faisalahmed.me/#
  
**Certificate Transparency**
- https://www.shodan.io/
- https://search.censys.io
- https://securitytrails.com
- https://en.fofa.info/

**Subdomain Enumeration**
- subfinder -d vulnweb.com >> subdomains_raw.txt
- assetfinder --subs-only vulnweb.com >> subdomains_raw.txt
- findomain -t vulnweb.com >> subdomains_raw.txt
- python3 sublist3r.py -d vulnweb.com -o sublist3r_output.txt
- sort -u subdomains.txt | grep vulnweb.com > subdomains_cleaned.txt
- dnsx -l subdomains_cleaned.txt -o resolved_subdomains.txt --silent
- httpx -l resolved_subdomains.txt -o live_subdomains.txt


**Check Subdomain Takeover Vulnerability**
- subzy run --targets live_subdomains.txt --vuln --output subzy_results.txt
- nuclei -l live_subdomains.txt -t ~/nuclei-templates/http/takeovers/ -o nuclei_takeover_results.txt
- subjack -w live_subdomains.txt -t 100 -timeout 30 -ssl -c ~/BUGBOUNTY/fingerprints.json -v -o subjack_results.txt

**Find IP Address with Domain**
- subfinder -d "example.com" -recursive -all -silent | subprober -ip | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u | tee ips.txt 
- nmap -iL ips.txt -sV

**Directory and File Brute Forcing**

- sudo dirsearch -l live_subdomains.txt \
  --exclude-status 400,401,402,403,404,429,500,501,502,503 \
  --include-status 200,301,302 \
  -e html,php,txt,pdf,js,css,zip,bak,old,log,json,xml,config,env,asp,aspx,jsp,gz,tar,sql,db \
  --full-url --recursive --max-recursion-depth=3 \
  --random-agent \
  --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0)" \
  --header "X-Forwarded-For: 127.0.0.1" \
  -t 20 \
  --output dirsearch_results.txt


- feroxbuster -u https://my.vultr.com/ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt \
  --insecure -d 2 -L 4 -e -t 20 \
  --random-agent \
  --rate-limit 5 \
  --silent \
  --output feroxbuster_results.txt

- ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt \
  -u https://my.vultr.com/FUZZ \
  -fc 400,401,402,403,404,429,500,501,502,503 \
  -mc 200,301,302 \
  -recursion -recursion-depth 2 \
  -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db \
  -rate 50 \
  --timeout 10 \
  -ac \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0)" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -o ffuf_results.txt

**URL Crawling**
- cat live_subdomains.txt | gau | tee gau.txt
- cat live_subdomains.txt | waybackurls | tee wayback.txt
- waymore -i "live_subdomains.txt" -n -mode U -oU waymore.txt
- cat gau.txt wayback.txt waymore.txt | sort -u > all_urls.txt
- cat all_urls.txt | httprobe -c 50 > live_urls.txt

**Find JavaScript File Vulnerability**
- cat live_urls.txt | grep ".js$" >> js.txt
- nuclei -l js.txt -rl 25 -t ~/nuclei-templates/http/exposures/ -o js_bugs.txt
- nuclei -l live_subdomains.txt -rl 15 -o Nuclei_bugs.txt

## SIGNUP PAGE FUNCTIONALITY VULNERABILITIES 

**1. No Rate Limit at Signup Page**
- Enter your details in signup form and submit the form
- Capture the signup request and send it to intruder
- add $$ to email parameter
- In the payload add different email address
- Fire up intruder and check whether it return 200 ok

**2. Hyper Link Injection Vulnerability**
- Visit the target website's registration page.
- Enter evil.com (or any malicious URL) as the First Name and Last Name field.
- Complete the registration process with valid details.
- Now check  your email  and you notice there is malicious hyperlinks.

**3. Server Side Template Injection**
- Navigate to the Signup page.
- Now, in the First Name field, enter the value {{7*7}}
- Fill in the rest of the values on the Register page and register your account.
- We have used the payload {{7*7}} here to verify that it is being evaluated at the backend.
- Now, wait for the welcome/promotional email to arrive in your Inbox.
- Notice that the email arrives with the Subject as 49.

**4. HTML Injection Vulnerability**
- Visit the target website's input fields (e.g., Registration Page, Feedback Form, Profile Update, or Search Bar).  
- Enter the following payloads on any user input field:  
  - `<h1>welcome</h1>`  
  - `<a href="https://evil.com">Click Me</a>`  
- Verify if the input is displayed directly on the website without escaping or sanitization.  

**5. Reflected XSS on Signup Page and Login Page**
- Go to `https://example.com/signup`.  
- Fill out the signup form but **do not submit** it.  
- Open **Burp Suite** and capture the submit request.  
- Modify the parameter values as follows:  
  - **Email Field**: Replace the email parameter with:  
    ```html
    <img src=x onerror=alert(document.domain)>
    ```
  - **Username Field**: Replace with:  
    ```html
    <svg/onload=confirm(1)>
    ```
  - Additional Payload for Email:  
    ```html
    a7madn1@gmail.com'"><svg/onload=alert(/xss/)>, “><svg/onload=confirm(1)>”@x.y
    ```
- Forward the request and turn the intercept off.  

**6. OAuth Redirect URI Manipulation**
- Go to the target website and initiate the **OAuth authorization flow**.
- Intercept the request using Burp Suite.
- Locate the `redirect_uri` parameter in the intercepted URL.
- Modify the `redirect_uri` value to an attacker-controlled malicious URL -  https://attacker.com/callback.
- Forward the modified request to the authorization server and continue with the OAuth flow.
- Observe if the server redirects you to the attacker-controlled website.

**7. Attacker creates an account**
- Attacker creates an account on the client application using the victim's email address (`victim@example.com`).
- The attacker is prompted to verify the email address, but does not complete the verification process.
- The victim register on the client application using a different signup method **OAuth flow** with the same email address (`victim@example.com`).
- The victim logs into the client application via the OAuth flow, successfully creating an account and bypassing the email verification process.
- The attacker logs into the client application using the victim’s email address and the attacker’s password.
- Observe if the attacker gains unauthorized access to the victim's account and can view or manipulate any data added by the victim.

**8. Reusability of an OAuth Access Token**
- Log in to the client application using your credentials via the OAuth flow and capture the access token issued by the authorization server using Burp Suite.
- Log out of the application to terminate your session.
- Intercept the logout request to ensure that no explicit token revocation request is sent to the authorization server.
- Attempt to use the previously captured access token to make an API request (e.g., access a protected resource).
- If the access token is still valid and the server processes the request successfully, the token is reusable post-logout, confirming the vulnerability.

**9. Reuse of Email for Multiple Accounts**
- Go to the target website's signup page.
- Register a new account using an email address (e.g., email@gmail.com).
- Attempt to create another account using the same email address with an alias (e.g., email+alias@gmail.com).
- Complete the registration process for both accounts.
- Observe if the system creates two separate accounts for the same email, bypassing validation.

**10. Weak Password Policy**
- Go to the target website's signup page.
- Register a new account with a weak or easily guessable password (e.g., 123456 or password).
- Complete the registration process.
- Log into the account using the weak password.
- Observe if the application allows the use of weak passwords without enforcing a strong password policy.

**11. Lack of Email Verification**
- Go to the target website's signup page.
- Register a new account using a fake or invalid email address (invalid@fakeemail.com).
- Complete the registration process without verifying the email address.
- Log into the account and perform normal operations.
- Observe if the account is functional despite the invalid or unverified email.



