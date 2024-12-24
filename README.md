# Bug Bounty Methodology
- **Dorking Search Engine** - https://freelancermijan.github.io/reconengine/, https://taksec.github.io/google-dorks-bug-bounty/, https://dorks.faisalahmed.me/#
- **Certificate Transparency** - https://www.shodan.io/, https://search.censys.io, https://securitytrails.com, https://en.fofa.info/

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
