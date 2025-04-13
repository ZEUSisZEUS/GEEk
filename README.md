 ██████╗ ███████╗███████╗██╗  ██╗
██╔════╝ ██╔════╝██╔════╝██║ ██╔╝
██║  ███╗█████╗  █████╗  █████╔╝ 
██║   ██║██╔══╝  ██╔══╝  ██╔═██╗ 
╚██████╔╝███████╗███████╗██║  ██╗
 ╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝

# 🌟 GEEk - Your Super Awesome Web Scanning Adventure Tool! 🌟

Yo, what's up? Welcome to **GEEk** (Grok's Epic Exploration Kit)! 🎉 This is your wicked cool tool for snooping around websites and uncovering all sorts of neat stuff. 🌐 Are you a hacker, a curious nerd, or just love geeking out over tech? GEEk is here to make it a blast! 🚀

This guide is your treasure map 🗺️ to mastering GEEk. We’ve got setup, what the results mean, fixes for when things go wonky, and ideas to make GEEk even cooler—all in this one snazzy txt file. It’s packed with emojis 😎, spaced out to keep it chill, and designed to be fun to read. Let’s roll! 🛹

## 📂 What’s Inside the GEEk Stash? 🗃️

Here’s the lowdown on how GEEk keeps its goodies organized:

GEEk/
├── config.ini              # ⚙️ Settings to tweak GEEk’s vibe
├── geek.py                 # 🧠 The main brain of GEEk!
├── wordlists/              # 📜 Folder with lists for sneaky scans
│   ├── dirb_common.txt     # 🗂️ Common website folders to poke at
│   └── subdomains.txt      # 🌍 Common subdomains to hunt
├── reports/                # 📊 Where GEEk spills its findings
├── report_template.html    # 🎨 Template for slick HTML reports
└── web_recon.log           # 🕵️ Log file to crack mysteries

🔥 **Hot Tip**: Those wordlists are like secret codes for finding hidden web treasures. Guard ‘em like gold! 💰

## 🛠️ How to Rock GEEk - Your Step-by-Step Quest 🎮

GEEk is a breeze to use, even if you’re just starting out. Follow this path to start your adventure:

1. **Gear Up GEEk** ⚡:
   - Got Python 3? Check it by typing in your terminal:
     python3 --version
   - Snag the needed tools with this magic spell:
     pip install requests aiohttp python-whois python-nmap beautifulsoup4 rich fake-useragent cryptography dnspython pyOpenSSL shodan censys jinja2 pandas matplotlib Pillow
   - Want fancy PDF reports? Grab this too (on Linux):
     sudo apt-get install wkhtmltopdf
   - Got API keys for Shodan, Censys, VirusTotal, or SecurityTrails? Pop ‘em in config.ini:
     [api]
     shodan_key = YOUR_SHODAN_KEY
     censys_id = YOUR_CENSYS_ID
     censys_secret = YOUR_CENSYS_SECRET
     virustotal_key = YOUR_VIRUSTOTAL_KEY
     securitytrails_key = YOUR_SECURITYTRAILS_KEY

2. **Launch Your Scan** 🚀:
   - Open your terminal, hop into the GEEk folder, and type:
     python3 geek.py example.com
   - Swap example.com for your target, like http://example.com if you want.

3. **Watch the Show** 🎬:
   - GEEk will fire up with a cool progress bar, scanning ports, subdomains, vulnerabilities, and more!
   - When it’s done, you’ll find reports in the reports/ folder in JSON, CSV, HTML, Markdown, and XML flavors.

4. **Check Your Loot** 💎:
   - Head to the reports/ folder for files like example.com_TIMESTAMP.json.
   - Open the HTML report in a browser for a shiny view, or dig into the JSON for all the juicy details.

## 🧐 What Do All These Scan Results Mean? 🔍

GEEk dishes out a ton of info. Here’s the scoop on what it all means:

- **Port Scanning** 🔌:
  - Shows open ports like 80 (HTTP) or 443 (HTTPS).
  - Open ports spill the beans on what’s running. Port 22 (SSH) could be a door if it’s not locked tight.
  - Weird ports like 3306 (MySQL) open? That’s a red flag for exposure!

- **Subdomain Scan** 🌍:
  - Lists stuff like blog.example.com or admin.example.com.
  - Subdomains can uncover hidden corners. An admin one might be a goldmine!
  - “Takeovers” mean a subdomain points to an unclaimed service (like AWS), ripe for sneaking in.

- **Directory Scan** 🗂️:
  - Finds folders like /admin or /backup.
  - Hidden folders might hold goodies like backups or secret configs.

- **Vulnerabilities** ⚠️:
  - Hunts for nasties like XSS (evil scripts), SQL injection (database hacks), or open redirects (tricking users).
  - Found something? The report pinpoints where the site might be weak.

- **Headers** 🛡️:
  - Checks security headers like Content-Security-Policy.
  - Missing ones (like X-Frame-Options) could let hackers pull tricks like clickjacking.

- **SSL/TLS** 🔒:
  - Looks at the site’s encryption (HTTPS).
  - Weak ciphers or old protocols (like SSLv3) scream “update me!”

- **WHOIS** 🕵️‍♂️:
  - Tells you who owns the domain and when it expires.
  - Handy to check if a domain’s legit or might be up for grabs soon.

- **CMS Detection** 🖥️:
  - Spots if the site uses WordPress, Joomla, or others.
  - Old CMS versions are like open doors for hackers.

- **Email Security** ✉️:
  - Checks SPF, DKIM, and DMARC for email protection.
  - No records? Someone could fake the site’s emails.

**Example Result** (from JSON):
{
  "port_scanning": {
    "tcp_ports": [{"port": 80, "state": "open", "service": "http"}],
    "udp_ports": []
  },
  "subdomain_scan": {
    "dns_bruteforce": [{"subdomain": "blog.example.com", "ip": ["192.0.2.1"]}]
  },
  "vulnerabilities": {
    "common": {"xss": [{"url": "http://example.com?q=<script>", "payload": "<script>"}]}
  }
}
Translation: Port 80 is open (website running), found a blog subdomain, and there’s a possible XSS hole to watch out for!

## 😵 Troubleshooting - When GEEk Gets Grumpy

If GEEk throws a fit, no stress! Here’s how to get it back on track:

1. **Missing Libraries** 📚:
   - Seeing “ModuleNotFoundError”?
   - Cast the pip spell again:
     pip install requests aiohttp python-whois python-nmap beautifulsoup4 rich fake-useragent cryptography dnspython pyOpenSSL shodan censys jinja2 pandas matplotlib Pillow
   - Still cranky? Force it:
     pip install --force-reinstall -r requirements.txt
     (Make a requirements.txt with those libraries if you need to.)

2. **Wordlist Woes** 📜:
   - GEEk whining “wordlist not found”? The wordlists/ folder might be acting up.
   - **Easy Fix**: Zap the wordlists/ folder and retry:
     rm -rf wordlists/
     GEEk will skip those scans but keep going.
   - **Don’t Wanna Delete?** Check for dirb_common.txt and subdomains.txt:
     ls wordlists/
   - Missing? Whip ‘em up:
     echo -e "admin\nlogin\nbackup" > wordlists/dirb_common.txt
     echo -e "blog\nmail\napi" > wordlists/subdomains.txt

3. **Permission Pouts** 🔐:
   - Linux scans like SYN need superpowers:
     sudo python3 geek.py example.com
   - No sudo? Tweak config.ini for connect scans:
     [scanning]
     scan_type = connect

4. **Network Nags** 🌐:
   - Timeouts or connection hiccups? Test your net:
     ping google.com
   - Bump up the timeout in config.ini:
     [general]
     timeout = 20

5. **Log Sleuthing** 🕵️:
   - Peek at web_recon.log for hints:
     cat web_recon.log
   - Hunt for “ERROR”:
     grep "ERROR" web_recon.log

**Fix Without Deleting Wordlists**:
Add this to the dir_scan method in geek.py if wordlists keep breaking:
import os
wordlist_path = self.config['scanning']['wordlist']
if not os.path.exists(wordlist_path):
    logger.warning(f"Wordlist {wordlist_path} not found, creating default")
    os.makedirs(os.path.dirname(wordlist_path), exist_ok=True)
    with open(wordlist_path, 'w') as f:
        f.write("admin\nlogin\nbackup")
This auto-makes a basic wordlist if it’s missing.

## 🚀 Leveling Up GEEk - Make It Epic!

GEEk’s already awesome, but you can make it *next-level*. Try these hacks:

1. **Email Alerts** 📧:
   - Get scan results emailed to you.
   - Add to generate_reports in geek.py:
     import smtplib
     from email.mime.text import MIMEText
     msg = MIMEText(json.dumps(self.results, indent=2))
     msg['Subject'] = f'GEEk Scan Results for {self.target}'
     msg['From'] = 'your_email@gmail.com'
     msg['To'] = 'your_email@gmail.com'
     with smtplib.SMTP('smtp.gmail.com', 587) as server:
         server.starttls()
         server.login('your_email@gmail.com', 'your_password')
         server.send_message(msg)

2. **Custom Wordlists** 📝:
   - Use your own sneaky list.
   - Update config.ini:
     [scanning]
     wordlist = my_wordlist.txt
   - Make it:
     echo -e "dashboard\nconfig\nsecret" > wordlists/my_wordlist.txt

3. **Vulnerability Hunter** 🐞:
   - Check for outdated software.
   - Add to vulnerability_checks in geek.py:
     async def check_outdated_software(self):
         outdated = []
         if 'cms' in self.results and self.results['cms'] == 'WordPress':
             version = await self.get_wordpress_version()
             if version and version < '6.0':
                 outdated.append({'software': 'WordPress', 'version': version, 'risk': 'High'})
         return outdated

4. **Website Snapshots** 📸:
   - Snap pics of pages found.
   - Add to dir_scan in geek.py:
     from selenium import webdriver
     driver = webdriver.Chrome()
     for result in found:
         driver.get(result['url'])
         driver.save_screenshot(f"reports/{result['url'].replace('/', '_')}.png")
     driver.quit()

## 🐧 Linux Love - Special Tips

Linux folks, here’s some extra sauce:

- **Grab Dependencies**:
  sudo apt-get update
  sudo apt-get install python3 python3-pip nmap wkhtmltopdf
  pip3 install requests aiohttp python-whois python-nmap beautifulsoup4 rich fake-useragent cryptography dnspython pyOpenSSL shodan censys jinja2 pandas matplotlib Pillow

- **Run Like a Boss**:
  sudo python3 geek.py example.com
  Unlocks SYN scans and OS detection.

- **Live Log Vibes**:
  tail -f web_recon.log
  See errors as they happen.

- **Auto-Scan Life**:
  Add to crontab:
    crontab -e
    0 0 * * * /usr/bin/python3 /path/to/GEEk/geek.py example.com
  Scans example.com every midnight.

ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
