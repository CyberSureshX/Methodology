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
