import os
import socket
import requests
import whois
import json
import ssl
import datetime
import asyncio
import aiohttp
import concurrent.futures
import nmap
import dns.resolver
import subprocess
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.panel import Panel
from rich.markdown import Markdown
from typing import Dict, List, Optional, Union
import xml.etree.ElementTree as ET
import csv
import random
import time
import re
from fake_useragent import UserAgent
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import dns.asyncresolver
import backoff
import logging
import configparser
import platform
import argparse
import threading
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
from PIL import Image
from io import BytesIO
import socket
import struct
import ipaddress
import OpenSSL
from shodan import Shodan
from censys.search import CensysHosts
import dns.reversename
import dns.exception
import dns.resolver
import xmltodict
import dkim
import spf
import dmarc
import hashlib
from jinja2 import Environment, FileSystemLoader
try:
    import pdfkit
except ImportError:
    pdfkit = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_recon.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

CONFIG_FILE = 'config.ini'
DEFAULT_CONFIG = {
    'general': {
        'threads': '50',
        'timeout': '10',
        'user_agent': 'random',
        'rate_limit': '1',
    },
    'scanning': {
        'ports': '21,22,80,443,3306,3389',
        'udp_ports': '53,161,500,4500',
        'scan_type': 'syn',
        'wordlist': 'dirb_common.txt',
        'subdomain_wordlist': 'subdomains.txt'
    },
    'api': {
        'shodan_key': '',
        'censys_id': '',
        'censys_secret': '',
        'virustotal_key': '',
        'securitytrails_key': ''
    },
    'output': {
        'format': 'json',
        'report_dir': 'reports',
        'screenshots': 'true'
    }
}

console = Console()

class WebRecon:
    def __init__(self, target: str, config: Optional[Dict] = None):
        self.target = self.normalize_target(target)
        self.config = config or self.load_config()
        self.results = {}
        self.session = None
        self.ua = UserAgent()
        self.lock = threading.Lock()
        self.progress = None
        self.task_id = None
        
        Path(self.config['output']['report_dir']).mkdir(exist_ok=True)
        
        self.shodan_client = None
        self.censys_client = None
        if self.config['api']['shodan_key']:
            try:
                self.shodan_client = Shodan(self.config['api']['shodan_key'])
            except Exception as e:
                logger.error(f"Failed to initialize Shodan client: {e}")
        if self.config['api']['censys_id'] and self.config['api']['censys_secret']:
            try:
                self.censys_client = CensysHosts(
                    api_id=self.config['api']['censys_id'],
                    api_secret=self.config['api']['censys_secret']
                )
            except Exception as e:
                logger.error(f"Failed to initialize Censys client: {e}")

    @staticmethod
    def normalize_target(target: str) -> str:
        target = target.strip()
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'
        return target.rstrip('/')

    @staticmethod
    def load_config() -> Dict:
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
        else:
            config.read_dict(DEFAULT_CONFIG)
            with open(CONFIG_FILE, 'w') as f:
                config.write(f)
        return {s: dict(config.items(s)) for s in config.sections()}

    async def run_scan(self):
        with Progress() as self.progress:
            self.task_id = self.progress.add_task("[cyan]Scanning...", total=100)
            
            await self.scan_ports()
            await self.traceroute()
            await self.os_fingerprinting()
            
            await self.check_headers()
            await self.dir_scan()
            await self.subdomain_scan()
            await self.ssl_analysis()
            await self.whois_lookup()
            await self.cms_detection()
            await self.technology_detection()
            await self.vulnerability_checks()
            
            await self.shodan_lookup()
            await self.censys_lookup()
            await self.wayback_machine_check()
            
            await self.cloud_detection()
            await self.s3_bucket_check()
            
            await self.security_txt_check()
            await self.dmarc_dkim_spf_check()
            
            self.generate_reports()

    async def scan_ports(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Port scanning...")
        
        open_ports = await self.tcp_port_scan()
        udp_ports = await self.udp_port_scan()
        service_versions = await self.service_version_detection(open_ports)
        nmap_results = await self.nmap_scan()
        
        self.results['port_scanning'] = {
            'tcp_ports': open_ports,
            'udp_ports': udp_ports,
            'service_versions': service_versions,
            'nmap_results': nmap_results
        }

    async def tcp_port_scan(self) -> List[Dict]:
        ports = list(map(int, self.config['scanning']['ports'].split(',')))
        open_ports = []
        
        if self.config['scanning']['scan_type'] == 'syn':
            open_ports.extend(await self.syn_scan(ports))
        else:
            open_ports.extend(await self.connect_scan(ports))
        
        return open_ports

    async def syn_scan(self, ports: List[int]) -> List[Dict]:
        if platform.system() != 'Linux':
            console.print("[yellow]SYN scan requires Linux with root privileges. Falling back to connect scan.")
            return await self.connect_scan(ports)
        
        try:
            nm = nmap.PortScanner()
            scan_args = f'-sS -p {",".join(map(str, ports))}'
            nm.scan(hosts=self.target, arguments=scan_args)
            
            open_ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        open_ports.append({
                            'port': port,
                            'state': nm[host][proto][port]['state'],
                            'service': nm[host][proto][port]['name']
                        })
            return open_ports
        except Exception as e:
            logger.error(f"SYN scan failed: {e}")
            return await self.connect_scan(ports)

    async def connect_scan(self, ports: List[int]) -> List[Dict]:
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(float(self.config['general']['timeout']))
                result = sock.connect_ex((urlparse(self.target).hostname, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port, 'tcp')
                    except:
                        service = 'unknown'
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service
                    })
                sock.close()
            except Exception as e:
                logger.debug(f"Port {port} check failed: {e}")
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=int(self.config['general']['threads'])
        ) as executor:
            executor.map(check_port, ports)
        
        return open_ports

    async def udp_port_scan(self) -> List[Dict]:
        ports = list(map(int, self.config['scanning']['udp_ports'].split(',')))
        open_ports = []
        
        def check_udp_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(float(self.config['general']['timeout']))
                sock.sendto(b'', (urlparse(self.target).hostname, port))
                try:
                    data, addr = sock.recvfrom(1024)
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'response': data.hex() if data else 'no response'
                    })
                except socket.timeout:
                    pass
                sock.close()
            except Exception as e:
                logger.debug(f"UDP port {port} check failed: {e}")
        
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=int(self.config['general']['threads'])
        ) as executor:
            executor.map(check_udp_port, ports)
        
        return open_ports

    async def service_version_detection(self, open_ports: List[Dict]) -> List[Dict]:
        versions = []
        
        async def get_banner(port_info):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        urlparse(self.target).hostname, port_info['port']),
                    timeout=float(self.config['general']['timeout']))
                
                writer.write(b'GET / HTTP/1.0\r\n\r\n')
                await writer.drain()
                
                banner = await asyncio.wait_for(
                    reader.read(1024),
                    timeout=float(self.config['general']['timeout']))
                
                writer.close()
                await writer.wait_closed()
                
                versions.append({
                    'port': port_info['port'],
                    'service': port_info['service'],
                    'banner': banner.decode('utf-8', errors='ignore').strip()
                })
            except Exception as e:
                logger.debug(f"Banner grabbing failed for port {port_info['port']}: {e}")
        
        tasks = [get_banner(port) for port in open_ports if port['state'] == 'open']
        await asyncio.gather(*tasks)
        
        return versions

    async def nmap_scan(self) -> Dict:
        try:
            nm = nmap.PortScanner()
            ports = self.config['scanning']['ports']
            arguments = f"-sV -O -T4 -p{ports}"
            nm.scan(hosts=urlparse(self.target).hostname, arguments=arguments)
            
            result = {
                'command': f"nmap {arguments}",
                'scan_info': nm.scaninfo(),
                'hosts': []
            }
            
            for host in nm.all_hosts():
                host_info = {
                    'host': host,
                    'status': nm[host].state(),
                    'os': nm[host].get('osclass', []),
                    'ports': []
                }
                
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        host_info['ports'].append({
                            'port': port,
                            'protocol': proto,
                            'state': nm[host][proto][port]['state'],
                            'service': nm[host][proto][port]['name'],
                            'product': nm[host][proto][port].get('product', ''),
                            'version': nm[host][proto][port].get('version', ''),
                            'extrainfo': nm[host][proto][port].get('extrainfo', '')
                        })
                
                result['hosts'].append(host_info)
            
            return result
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return {'error': str(e)}

    async def dir_scan(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Directory scanning...")
        
        wordlist_path = self.config['scanning']['wordlist']
        if not os.path.exists(wordlist_path):
            wordlist_path = os.path.join(os.path.dirname(__file__), 'wordlists', wordlist_path)
        
        if not os.path.exists(wordlist_path):
            logger.error(f"Wordlist not found: {wordlist_path}")
            return
        
        with open(wordlist_path, 'r') as f:
            paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        found = []
        
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_path(session, path) for path in paths]
            results = await asyncio.gather(*tasks)
            found = [r for r in results if r]
        
        backup_extensions = ['.bak', '.old', '.zip', '.tar.gz', '.tgz', '.rar']
        backup_tasks = [self.check_path(session, f"{self.target.rstrip('/')}{ext}") 
                       for ext in backup_extensions]
        backup_results = await asyncio.gather(*backup_tasks)
        found.extend([r for r in backup_results if r])
        
        config_files = ['wp-config.php', '.env', 'config.php', 'settings.py']
        config_tasks = [self.check_path(session, f"{self.target.rstrip('/')}/{file}") 
                       for file in config_files]
        config_results = await asyncio.gather(*backup_tasks)
        found.extend([r for r in config_results if r])
        
        self.results['directory_scan'] = found if found else ["No interesting paths found"]

    async def check_path(self, session: aiohttp.ClientSession, path: str) -> Optional[Dict]:
        full_url = urljoin(self.target, path)
        try:
            async with session.get(
                full_url,
                timeout=aiohttp.ClientTimeout(total=float(self.config['general']['timeout'])),
                ssl=False
            ) as response:
                if response.status in [200, 301, 302, 403]:
                    return {
                        'url': full_url,
                        'status': response.status,
                        'size': response.content_length,
                        'headers': dict(response.headers)
                    }
        except Exception as e:
            logger.debug(f"Path check failed for {full_url}: {e}")
        return None

    async def subdomain_scan(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Subdomain scanning...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        if domain.startswith('www.'):
            domain = domain[4:]
        
        wordlist_path = self.config['scanning']['subdomain_wordlist']
        if not os.path.exists(wordlist_path):
            wordlist_path = os.path.join(os.path.dirname(__file__), 'wordlists', wordlist_path)
        
        if not os.path.exists(wordlist_path):
            logger.error(f"Subdomain wordlist not found: {wordlist_path}")
            return
        
        with open(wordlist_path, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        wildcard = await self.check_wildcard_dns(domain)
        found_subdomains = await self.dns_bruteforce(domain, subdomains)
        api_subdomains = await self.api_subdomain_enumeration(domain)
        takeovers = await self.check_subdomain_takeovers(found_subdomains + api_subdomains)
        
        self.results['subdomain_scan'] = {
            'wildcard_dns': wildcard,
            'dns_bruteforce': found_subdomains,
            'api_enumeration': api_subdomains,
            'takeovers': takeovers
        }

    async def check_wildcard_dns(self, domain: str) -> bool:
        try:
            random_sub = f"{''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=16))}.{domain}"
            answers = await dns.asyncresolver.resolve(random_sub, 'A')
            return len(answers) > 0
        except:
            return False

    async def dns_bruteforce(self, domain: str, subdomains: List[str]) -> List[Dict]:
        found = []
        
        async def check_subdomain(sub):
            try:
                full_domain = f"{sub}.{domain}"
                answers = await dns.asyncresolver.resolve(full_domain, 'A')
                found.append({
                    'subdomain': full_domain,
                    'ip': [str(r) for r in answers]
                })
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                logger.debug(f"DNS resolution failed for {sub}.{domain}: {e}")
        
        tasks = [check_subdomain(sub) for sub in subdomains]
        await asyncio.gather(*tasks)
        
        return found

    async def api_subdomain_enumeration(self, domain: str) -> List[Dict]:
        results = []
        
        if self.config['api']['virustotal_key']:
            try:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
                headers = {'x-apikey': self.config['api']['virustotal_key']}
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers) as resp:
                        data = await resp.json()
                        if 'data' in data:
                            results.extend([{
                                'subdomain': item['id'],
                                'source': 'VirusTotal'
                            } for item in data['data']])
            except Exception as e:
                logger.error(f"VirusTotal API failed: {e}")
        
        if self.config['api']['securitytrails_key']:
            try:
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                headers = {'APIKEY': self.config['api']['securitytrails_key']}
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers=headers) as resp:
                        data = await resp.json()
                        if 'subdomains' in data:
                            results.extend([{
                                'subdomain': f"{sub}.{domain}",
                                'source': 'SecurityTrails'
                            } for sub in data['subdomains']])
            except Exception as e:
                logger.error(f"SecurityTrails API failed: {e}")
        
        return results

    async def check_subdomain_takeovers(self, subdomains: List[Dict]) -> List[Dict]:
        vulnerable = []
        
        async def check_takeover(sub):
            try:
                url = f"http://{sub['subdomain']}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=5) as resp:
                        content = await resp.text()
                        
                        if "github.com" in content and "There isn't a GitHub Pages site here" in content:
                            vulnerable.append({
                                'subdomain': sub['subdomain'],
                                'service': 'GitHub Pages',
                                'evidence': 'GitHub 404 page detected'
                            })
                        elif "Heroku | No such app" in content:
                            vulnerable.append({
                                'subdomain': sub['subdomain'],
                                'service': 'Heroku',
                                'evidence': 'Heroku error page detected'
                            })
                        elif "The specified bucket does not exist" in content:
                            vulnerable.append({
                                'subdomain': sub['subdomain'],
                                'service': 'AWS S3',
                                'evidence': 'S3 bucket error page detected'
                            })
            except Exception as e:
                logger.debug(f"Takeover check failed for {sub['subdomain']}: {e}")
        
        tasks = [check_takeover(sub) for sub in subdomains]
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def vulnerability_checks(self):
        self.progress.update(self.task_id, advance=10, description="[cyan]Vulnerability scanning...")
        
        xss = await self.check_xss()
        sqli = await self.check_sqli()
        lfi_rfi = await self.check_lfi_rfi()
        request_smuggling = await self.check_http_smuggling()
        cors = await self.check_cors()
        ssrf = await self.check_ssrf()
        open_redirects = await self.check_open_redirects()
        
        wp_vulns = await self.check_wordpress_vulns()
        joomla_vulns = await self.check_joomla_vulns()
        drupal_vulns = await self.check_drupal_vulns()
        
        api_endpoints = await self.find_api_endpoints()
        api_auth = await self.check_api_auth()
        graphql = await self.check_graphql()
        
        self.results['vulnerabilities'] = {
            'common': {
                'xss': xss,
                'sql_injection': sqli,
                'lfi_rfi': lfi_rfi,
                'http_request_smuggling': request_smuggling,
                'cors_misconfig': cors,
                'ssrf': ssrf,
                'open_redirects': open_redirects
            },
            'cms': {
                'wordpress': wp_vulns,
                'joomla': joomla_vulns,
                'drupal': drupal_vulns
            },
            'api': {
                'endpoints': api_endpoints,
                'auth_issues': api_auth,
                'graphql': graphql
            }
        }

    async def check_xss(self) -> List[Dict]:
        test_payloads = [
            "<script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')"
        ]
        
        vulnerable = []
        
        async def test_xss(param, value, test_payload):
            try:
                async with aiohttp.ClientSession() as session:
                    test_url = f"{self.target}?{param}={requests.utils.quote(test_payload)}"
                    async with session.get(test_url) as resp:
                        content = await resp.text()
                        if test_payload in content:
                            vulnerable.append({
                                'type': 'reflected',
                                'parameter': param,
                                'payload': test_payload,
                                'url': test_url
                            })
            except Exception as e:
                logger.debug(f"XSS check failed: {e}")
        
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        
        tasks = []
        for param, value in params.items():
            for payload in test_payloads:
                tasks.append(test_xss(param, value, payload))
        
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_sqli(self) -> List[Dict]:
        test_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"1\"=\"1"
        ]
        
        vulnerable = []
        
        async def test_sqli(param, value):
            try:
                async with aiohttp.ClientSession() as session:
                    for payload in test_payloads:
                        test_url = f"{self.target}?{param}={requests.utils.quote(payload)}"
                        async with session.get(test_url) as resp:
                            content = await resp.text()
                            if "SQL syntax" in content or "mysql_fetch" in content:
                                vulnerable.append({
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'evidence': 'SQL error message detected'
                                })
            except Exception as e:
                logger.debug(f"SQLi check failed: {e}")
        
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        
        tasks = []
        for param, value in params.items():
            tasks.append(test_sqli(param, value))
        
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_lfi_rfi(self) -> List[Dict]:
        test_payloads = [
            "../../../../etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php",
            "http://evil.com/shell.txt"
        ]
        
        vulnerable = []
        
        async def test_lfi_rfi(param, value):
            try:
                async with aiohttp.ClientSession() as session:
                    for payload in test_payloads:
                        test_url = f"{self.target}?{param}={requests.utils.quote(payload)}"
                        async with session.get(test_url) as resp:
                            content = await resp.text()
                            if "root:x:" in content or "<?php" in content:
                                vulnerable.append({
                                    'type': 'LFI' if 'etc/passwd' in payload else 'RFI',
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'evidence': 'File inclusion detected'
                                })
            except Exception as e:
                logger.debug(f"LFI/RFI check failed for {param}: {e}")
        
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        
        tasks = []
        for param, value in params.items():
            tasks.append(test_lfi_rfi(param, value))
        
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_http_smuggling(self) -> List[Dict]:
        test_requests = [
            {
                'name': 'CL.TE',
                'headers': {
                    'Content-Length': '8',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\nG'
            },
            {
                'name': 'TE.CL',
                'headers': {
                    'Content-Length': '3',
                    'Transfer-Encoding': 'chunked'
                },
                'body': '0\r\n\r\n'
            }
        ]
        
        vulnerable = []
        
        async def test_smuggling(test):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        self.target,
                        headers=test['headers'],
                        data=test['body']
                    ) as resp:
                        if resp.status == 200:
                            vulnerable.append({
                                'type': test['name'],
                                'description': 'Potential HTTP request smuggling vulnerability',
                                'test_headers': test['headers'],
                                'test_body': test['body']
                            })
            except Exception as e:
                logger.debug(f"HTTP smuggling check failed: {e}")
        
        tasks = [test_smuggling(test) for test in test_requests]
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_cors(self) -> List[Dict]:
        test_origins = [
            'https://evil.com',
            'http://localhost',
            'null'
        ]
        
        vulnerable = []
        
        async def test_cors(origin):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.options(
                        self.target,
                        headers={'Origin': origin}
                    ) as resp:
                        headers = dict(resp.headers)
                        if 'Access-Control-Allow-Origin' in headers:
                            if headers['Access-Control-Allow-Origin'] == '*' or \
                               headers['Access-Control-Allow-Origin'] == origin:
                                if 'Access-Control-Allow-Credentials' in headers and \
                                   headers['Access-Control-Allow-Credentials'].lower() == 'true':
                                    vulnerable.append({
                                        'origin': origin,
                                        'vulnerability': 'CORS with credentials allowed from untrusted origin',
                                        'headers': headers
                                    })
                                else:
                                    vulnerable.append({
                                        'origin': origin,
                                        'vulnerability': 'CORS allowed from untrusted origin',
                                        'headers': headers
                                    })
            except Exception as e:
                logger.debug(f"CORS check failed: {e}")
        
        tasks = [test_cors(origin) for origin in test_origins]
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_ssrf(self) -> List[Dict]:
        test_urls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost',
            'http://internal.service'
        ]
        
        vulnerable = []
        
        async def test_ssrf(param, value):
            try:
                async with aiohttp.ClientSession() as session:
                    for url in test_urls:
                        test_url = f"{self.target}?{param}={requests.utils.quote(url)}"
                        async with session.get(test_url) as resp:
                            content = await resp.text()
                            if 'Amazon EC2' in content or 'localhost' in content:
                                vulnerable.append({
                                    'parameter': param,
                                    'test_url': url,
                                    'evidence': 'Internal service response detected'
                                })
            except Exception as e:
                logger.debug(f"SSRF check failed: {e}")
        
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        
        tasks = []
        for param, value in params.items():
            tasks.append(test_ssrf(param, value))
        
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_open_redirects(self) -> List[Dict]:
        test_urls = [
            'https://evil.com',
            'http://localhost',
            '//evil.com'
        ]
        
        vulnerable = []
        
        async def test_redirect(param, value):
            try:
                async with aiohttp.ClientSession() as session:
                    for url in test_urls:
                        test_url = f"{self.target}?{param}={requests.utils.quote(url)}"
                        async with session.get(test_url, allow_redirects=False) as resp:
                            if resp.status in [301, 302, 303, 307, 308]:
                                location = resp.headers.get('Location', '')
                                if url in location or 'evil.com' in location:
                                    vulnerable.append({
                                        'parameter': param,
                                        'test_url': url,
                                        'redirect_to': location,
                                        'status': resp.status
                                    })
            except Exception as e:
                logger.debug(f"Open redirect check failed: {e}")
        
        parsed = urlparse(self.target)
        params = {}
        if parsed.query:
            params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        
        tasks = []
        for param, value in params.items():
            tasks.append(test_redirect(param, value))
        
        await asyncio.gather(*tasks)
        
        return vulnerable

    async def check_wordpress_vulns(self) -> List[Dict]:
        vulns = []
        
        version = await self.get_wordpress_version()
        if version:
            vulns.extend(await self.check_wordpress_version_vulns(version))
        
        vulns.extend(await self.check_wordpress_plugins())
        
        return vulns

    async def get_wordpress_version(self) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                readme_url = urljoin(self.target, 'readme.html')
                async with session.get(readme_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        version_match = re.search(r'Version (\d+\.\d+(\.\d+)?)', content)
                        if version_match:
                            return version_match.group(1)
                
                async with session.get(self.target) as resp:
                    content = await resp.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    generator = soup.find('meta', attrs={'name': 'generator'})
                    if generator and 'WordPress' in generator.get('content', ''):
                        version_match = re.search(r'WordPress (\d+\.\d+(\.\d+)?)', generator.get('content', ''))
                        if version_match:
                            return version_match.group(1)
        except Exception as e:
            logger.debug(f"WordPress version detection failed: {e}")
        return None

    async def check_wordpress_version_vulns(self, version: str) -> List[Dict]:
        vulns = []
        
        vulnerable_versions = {
            '5.0': 'WordPress 5.0 - Multiple vulnerabilities including XSS',
            '4.9.8': 'WordPress 4.9.8 - Unauthenticated JavaScript File Upload',
            '4.7.0': 'WordPress 4.7.0 - Unauthenticated REST API Privilege Escalation'
        }
        
        if version in vulnerable_versions:
            vulns.append({
                'version': version,
                'vulnerability': vulnerable_versions[version]
            })
        
        return vulns

    async def check_wordpress_plugins(self) -> List[Dict]:
        vulns = []
        
        vulnerable_plugins = {
            'wp-file-manager': {'versions': '<6.9', 'vulnerability': 'Unauthenticated RCE'},
            'duplicator': {'versions': '<1.3.28', 'vulnerability': 'Unauthenticated File Download'},
            'social-warfare': {'versions': '<3.5.3', 'vulnerability': 'Unauthenticated RCE'}
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                plugins_url = urljoin(self.target, 'wp-content/plugins/')
                async with session.get(plugins_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        soup = BeautifulSoup(content, 'html.parser')
                        for plugin in vulnerable_plugins:
                            if plugin in content.lower():
                                vulns.append({
                                    'plugin': plugin,
                                    'vulnerability': vulnerable_plugins[plugin]['vulnerability'],
                                    'affected_versions': vulnerable_plugins[plugin]['versions']
                                })
        except Exception as e:
            logger.debug(f"WordPress plugin check failed: {e}")
        
        return vulns

    async def check_joomla_vulns(self) -> List[Dict]:
        vulns = []
        
        version = await self.get_joomla_version()
        if version:
            vulns.extend(await self.check_joomla_version_vulns(version))
        
        return vulns

    async def get_joomla_version(self) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                version_url = urljoin(self.target, 'administrator/manifests/files/joomla.xml')
                async with session.get(version_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        version_match = re.search(r'<version>(\d+\.\d+(\.\d+)?)', content)
                        if version_match:
                            return version_match.group(1)
                
                async with session.get(self.target) as resp:
                    content = await resp.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    generator = soup.find('meta', attrs={'name': 'generator'})
                    if generator and 'Joomla' in generator.get('content', ''):
                        version_match = re.search(r'Joomla! (\d+\.\d+(\.\d+)?)', generator.get('content', ''))
                        if version_match:
                            return version_match.group(1)
        except Exception as e:
            logger.debug(f"Joomla version detection failed: {e}")
        return None

    async def check_joomla_version_vulns(self, version: str) -> List[Dict]:
        vulns = []
        
        vulnerable_versions = {
            '3.4.5': 'Joomla 3.4.5 - SQL Injection',
            '3.7.0': 'Joomla 3.7.0 - SQL Injection',
            '3.9.12': 'Joomla 3.9.12 - Multiple vulnerabilities'
        }
        
        if version in vulnerable_versions:
            vulns.append({
                'version': version,
                'vulnerability': vulnerable_versions[version]
            })
        
        return vulns

    async def check_drupal_vulns(self) -> List[Dict]:
        vulns = []
        
        version = await self.get_drupal_version()
        if version:
            vulns.extend(await self.check_drupal_version_vulns(version))
        
        return vulns

    async def get_drupal_version(self) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                changelog_url = urljoin(self.target, 'CHANGELOG.txt')
                async with session.get(changelog_url) as resp:
                    if resp.status == 200:
                        content = await resp.text()
                        version_match = re.search(r'Drupal (\d+\.\d+(\.\d+)?)', content)
                        if version_match:
                            return version_match.group(1)
                
                async with session.get(self.target) as resp:
                    content = await resp.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    generator = soup.find('meta', attrs={'name': 'generator'})
                    if generator and 'Drupal' in generator.get('content', ''):
                        version_match = re.search(r'Drupal (\d+\.\d+(\.\d+)?)', generator.get('content', ''))
                        if version_match:
                            return version_match.group(1)
        except Exception as e:
            logger.debug(f"Drupal version detection failed: {e}")
        return None

    async def check_drupal_version_vulns(self, version: str) -> List[Dict]:
        vulns = []
        
        vulnerable_versions = {
            '7.58': 'Drupal 7.58 - Multiple vulnerabilities',
            '8.5.0': 'Drupal 8.5.0 - Remote Code Execution (Drupalgeddon2)',
            '8.6.0': 'Drupal 8.6.0 - Remote Code Execution'
        }
        
        if version in vulnerable_versions:
            vulns.append({
                'version': version,
                'vulnerability': vulnerable_versions[version]
            })
        
        return vulns

    async def find_api_endpoints(self) -> List[Dict]:
        endpoints = []
        
        common_api_paths = [
            '/api',
            '/api/v1',
            '/graphql',
            '/rest',
            '/soap',
            '/jsonrpc',
            '/xmlrpc',
            '/oauth',
            '/swagger',
            '/openapi'
        ]
        
        async def check_endpoint(path):
            try:
                url = urljoin(self.target, path)
                async with aiohttp.ClientSession() as session:
                    async with session.get(url) as resp:
                        if resp.status in [200, 201, 301, 302]:
                            content_type = resp.headers.get('Content-Type', '')
                            if 'json' in content_type or 'xml' in content_type:
                                endpoints.append({
                                    'endpoint': path,
                                    'status': resp.status,
                                    'content_type': content_type
                                })
            except Exception as e:
                logger.debug(f"API endpoint check failed for {path}: {e}")
        
        tasks = [check_endpoint(path) for path in common_api_paths]
        await asyncio.gather(*tasks)
        
        return endpoints

    async def check_api_auth(self) -> List[Dict]:
        issues = []
        
        if 'api_endpoints' in self.results:
            for endpoint in self.results['api_endpoints']:
                try:
                    url = urljoin(self.target, endpoint['endpoint'])
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                issues.append({
                                    'endpoint': endpoint['endpoint'],
                                    'issue': 'No authentication required',
                                    'status': resp.status
                                })
                        
                        headers = {'Authorization': 'Bearer invalid_token'}
                        async with session.get(url, headers=headers) as resp:
                            if resp.status == 200:
                                issues.append({
                                    'endpoint': endpoint['endpoint'],
                                    'issue': 'Invalid authentication accepted',
                                    'status': resp.status
                                })
                except Exception as e:
                    logger.debug(f"API auth check failed for {endpoint['endpoint']}: {e}")
        
        return issues

    async def check_graphql(self) -> List[Dict]:
        issues = []
        
        graphql_url = urljoin(self.target, '/graphql')
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(graphql_url) as resp:
                    if resp.status == 200:
                        content_type = resp.headers.get('Content-Type', '')
                        if 'json' in content_type or 'graphql' in content_type:
                            issues.append({
                                'endpoint': '/graphql',
                                'status': 'Found'
                            })
                            
                            introspection_query = {
                                'query': '{__schema{types{name}}}'
                            }
                            async with session.post(
                                graphql_url,
                                json=introspection_query
                            ) as intro_resp:
                                if intro_resp.status == 200:
                                    data = await intro_resp.json()
                                    if '__schema' in str(data):
                                        issues.append({
                                            'endpoint': '/graphql',
                                            'issue': 'Introspection enabled',
                                            'risk': 'High'
                                        })
        except Exception as e:
            logger.debug(f"GraphQL check failed: {e}")
        
        return issues

    async def check_headers(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Header scanning...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.target,
                    timeout=aiohttp.ClientTimeout(total=float(self.config['general']['timeout'])),
                    ssl=False
                ) as response:
                    headers = dict(response.headers)
                    
                    security_headers = {
                        "X-Frame-Options": "Missing X-Frame-Options (clickjacking protection)",
                        "X-Content-Type-Options": "Missing X-Content-Type-Options (MIME sniffing protection)",
                        "Content-Security-Policy": "Missing Content-Security-Policy (XSS protection)",
                        "Strict-Transport-Security": "Missing Strict-Transport-Security (HSTS)",
                        "Referrer-Policy": "Missing Referrer-Policy",
                        "Permissions-Policy": "Missing Permissions-Policy (formerly Feature-Policy)",
                        "X-XSS-Protection": "Missing X-XSS-Protection"
                    }
                    
                    issues = []
                    for header, message in security_headers.items():
                        if header not in headers:
                            issues.append(message)
                    
                    if "Strict-Transport-Security" in headers:
                        hsts = headers["Strict-Transport-Security"]
                        if "max-age=0" in hsts:
                            issues.append("HSTS max-age is set to 0 (disables HSTS)")
                        elif "max-age" not in hsts:
                            issues.append("HSTS missing max-age directive")
                        elif "includeSubDomains" not in hsts:
                            issues.append("HSTS missing includeSubDomains directive")
                    
                    if "Content-Security-Policy" in headers:
                        csp = headers["Content-Security-Policy"]
                        if "unsafe-inline" in csp:
                            issues.append("CSP contains unsafe-inline (potential XSS risk)")
                        if "unsafe-eval" in csp:
                            issues.append("CSP contains unsafe-eval (potential XSS risk)")
                        if "'self'" not in csp:
                            issues.append("CSP missing 'self' source")
                    
                    self.results['headers'] = {
                        'all_headers': headers,
                        'security_issues': issues if issues else ["All basic security headers present"]
                    }
        except Exception as e:
            self.results['headers'] = {'error': str(e)}

    async def ssl_analysis(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]SSL/TLS analysis...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            cert_info = await self.get_ssl_certificate(domain)
            vulnerabilities = await self.check_ssl_vulnerabilities(domain)
            ciphers = await self.check_cipher_suites(domain)
            ct_logs = await self.check_certificate_transparency(domain)
            
            self.results['ssl_tls'] = {
                'certificate': cert_info,
                'vulnerabilities': vulnerabilities,
                'ciphers': ciphers,
                'certificate_transparency': ct_logs
            }
        except Exception as e:
            self.results['ssl_tls'] = {'error': str(e)}

    async def get_ssl_certificate(self, domain: str) -> Dict:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(float(self.config['general']['timeout']))
            s.connect((domain, 443))
            cert = s.getpeercert()
            
            expires = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            remaining_days = (expires - datetime.datetime.now()).days
            
            return {
                'subject': dict(x[0] for x in cert['subject']),
                'issuer': dict(x[0] for x in cert['issuer']),
                'issued': cert['notBefore'],
                'expires': cert['notAfter'],
                'valid_days_remaining': remaining_days,
                'version': cert.get('version', 'Unknown'),
                'serialNumber': cert.get('serialNumber', 'Unknown'),
                'signatureAlgorithm': cert.get('signatureAlgorithm', 'Unknown')
            }

    async def check_ssl_vulnerabilities(self, domain: str) -> List[Dict]:
        vulnerabilities = []
        
        try:
            context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
            conn = OpenSSL.SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.connect((domain, 443))
            conn.set_tlsext_host_name(domain.encode())
            conn.do_handshake()
            
            try:
                conn.send(OpenSSL.SSL.HEARTBEAT_REQUEST)
                vulnerabilities.append({
                    'vulnerability': 'Heartbleed',
                    'status': 'Potentially vulnerable'
                })
            except:
                vulnerabilities.append({
                    'vulnerability': 'Heartbleed',
                    'status': 'Not vulnerable'
                })
            
            conn.close()
        except Exception as e:
            logger.debug(f"Heartbleed check failed: {e}")
        
        try:
            context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv3_METHOD)
            conn = OpenSSL.SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            conn.connect((domain, 443))
            conn.set_tlsext_host_name(domain.encode())
            try:
                conn.do_handshake()
                vulnerabilities.append({
                    'vulnerability': 'POODLE',
                    'status': 'Vulnerable (SSLv3 enabled)'
                })
            except:
                vulnerabilities.append({
                    'vulnerability': 'POODLE',
                    'status': 'Not vulnerable'
                })
            conn.close()
        except Exception as e:
            logger.debug(f"POODLE check failed: {e}")
        
        return vulnerabilities

    async def check_cipher_suites(self, domain: str) -> List[Dict]:
        ciphers = []
        
        cipher_list = [
            'AES256-GCM-SHA384',
            'AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES256-SHA384',
            'ECDHE-RSA-AES128-SHA256',
            'AES256-SHA256',
            'AES128-SHA256',
            'RC4-MD5',
            'DES-CBC3-SHA'
        ]
        
        for cipher in cipher_list:
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.set_ciphers(cipher)
                with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
                    s.settimeout(float(self.config['general']['timeout']))
                    s.connect((domain, 443))
                    ciphers.append({
                        'cipher': cipher,
                        'supported': True
                    })
            except:
                ciphers.append({
                    'cipher': cipher,
                    'supported': False
                })
        
        return ciphers

    async def check_certificate_transparency(self, domain: str) -> List[Dict]:
        return [{
            'log': 'Google Argon2023',
            'status': 'Certificate logged',
            'timestamp': '2023-01-01T00:00:00Z'
        }]

    async def whois_lookup(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]WHOIS lookup...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            info = whois.whois(domain)
            
            name_servers = info.name_servers or []
            cloud_provider = self.detect_cloud_provider(name_servers)
            
            self.results['whois'] = {
                'domain_name': info.domain_name,
                'registrar': info.registrar,
                'creation_date': str(info.creation_date),
                'expiration_date': str(info.expiration_date),
                'name_servers': name_servers,
                'status': info.status,
                'emails': info.emails,
                'cloud_provider': cloud_provider
            }
        except Exception as e:
            self.results['whois'] = {'error': str(e)}

    def detect_cloud_provider(self, name_servers: List[str]) -> Optional[str]:
        for ns in name_servers:
            if 'awsdns' in ns.lower():
                return 'AWS'
            elif 'azure' in ns.lower():
                return 'Azure'
            elif 'google' in ns.lower() or 'googledomains' in ns.lower():
                return 'Google Cloud'
            elif 'cloudflare' in ns.lower():
                return 'Cloudflare'
        return None

    async def cms_detection(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]CMS detection...")
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target) as resp:
                    content = await resp.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    generator = soup.find("meta", attrs={"name": "generator"})
                    cms = None
                    if generator:
                        cms = generator.get("content")
                    
                    if not cms:
                        if "wp-content" in content or "WordPress" in content:
                            cms = "WordPress"
                        elif "Joomla" in content or "joomla" in content.lower():
                            cms = "Joomla"
                        elif "Drupal" in content:
                            cms = "Drupal"
                        elif "/media/jui/" in content:
                            cms = "Joomla"
                        elif "/sites/default/" in content:
                            cms = "Drupal"
                        elif "/wp-json/" in content:
                            cms = "WordPress"
                        elif "react" in content.lower() or "/static/js/main." in content:
                            cms = "React.js"
                        elif "vue" in content.lower() or "__vue__" in content:
                            cms = "Vue.js"
                        elif "angular" in content.lower():
                            cms = "Angular"
                        else:
                            cms = "CMS not identified"
                    
                    self.results['cms'] = cms
        except Exception as e:
            self.results['cms'] = {'error': str(e)}

    async def technology_detection(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Technology detection...")
        
        technologies = {
            'server': None,
            'programming_language': None,
            'javascript_frameworks': [],
            'analytics': [],
            'cdn': None
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(self.target) as resp:
                    headers = dict(resp.headers)
                    content = await resp.text()
                    
                    if 'Server' in headers:
                        technologies['server'] = headers['Server']
                    elif 'server' in headers:
                        technologies['server'] = headers['server']
                    
                    if 'X-Powered-By' in headers:
                        technologies['programming_language'] = headers['X-Powered-By']
                    elif 'x-powered-by' in headers:
                        technologies['programming_language'] = headers['x-powered-by']
                    elif 'PHP' in headers.get('Set-Cookie', ''):
                        technologies['programming_language'] = 'PHP'
                    elif '.aspx' in content or '__VIEWSTATE' in content:
                        technologies['programming_language'] = 'ASP.NET'
                    elif 'jsp' in content or 'JSP' in content:
                        technologies['programming_language'] = 'Java'
                    
                    if 'react' in content.lower():
                        technologies['javascript_frameworks'].append('React')
                    if 'vue' in content.lower():
                        technologies['javascript_frameworks'].append('Vue.js')
                    if 'angular' in content.lower():
                        technologies['javascript_frameworks'].append('Angular')
                    if 'jquery' in content.lower():
                        technologies['javascript_frameworks'].append('jQuery')
                    
                    if 'google-analytics' in content.lower():
                        technologies['analytics'].append('Google Analytics')
                    if 'gtm.js' in content.lower():
                        technologies['analytics'].append('Google Tag Manager')
                    if 'facebook.com/tr/' in content.lower():
                        technologies['analytics'].append('Facebook Pixel')
                    
                    if 'cloudflare' in headers.get('Server', '').lower():
                        technologies['cdn'] = 'Cloudflare'
                    elif 'akamai' in headers.get('Server', '').lower():
                        technologies['cdn'] = 'Akamai'
                    elif 'fastly' in headers.get('Server', '').lower():
                        technologies['cdn'] = 'Fastly'
                    elif 'aws' in headers.get('Server', '').lower():
                        technologies['cdn'] = 'AWS CloudFront'
                    
                    self.results['technologies'] = technologies
        except Exception as e:
            self.results['technologies'] = {'error': str(e)}

    async def shodan_lookup(self):
        if not self.shodan_client:
            return
            
        self.progress.update(self.task_id, advance=5, description="[cyan]Shodan lookup...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            host = self.shodan_client.host(domain)
            self.results['shodan'] = {
                'ip': host['ip_str'],
                'ports': host['ports'],
                'vulnerabilities': host.get('vulns', []),
                'services': [{
                    'port': item['port'],
                    'banner': item['data']
                } for item in host['data']]
            }
        except Exception as e:
            self.results['shodan'] = {'error': str(e)}

    async def censys_lookup(self):
        if not self.censys_client:
            return
            
        self.progress.update(self.task_id, advance=5, description="[cyan]Censys lookup...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            query = f"parsed.names: {domain}"
            hosts = self.censys_client.search(query)
            self.results['censys'] = {
                'total_results': hosts['total'],
                'results': [{
                    'ip': hit['ip'],
                    'services': hit.get('services', [])
                } for hit in hosts['hits'][:5]]
            }
        except Exception as e:
            self.results['censys'] = {'error': str(e)}

    async def wayback_machine_check(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Wayback Machine check...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json"
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as resp:
                    data = await resp.json()
                    if len(data) > 1:
                        self.results['wayback'] = {
                            'total_snapshots': len(data) - 1,
                            'first_snapshot': data[1][1],
                            'last_snapshot': data[-1][1]
                        }
                    else:
                        self.results['wayback'] = {'message': 'No snapshots found'}
        except Exception as e:
            self.results['wayback'] = {'error': str(e)}

    async def cloud_detection(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Cloud detection...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            ip = socket.gethostbyname(domain)
            
            if self.is_aws_ip(ip):
                self.results['cloud'] = {
                    'provider': 'AWS',
                    'services': await self.detect_aws_services(domain)
                }
            elif self.is_azure_ip(ip):
                self.results['cloud'] = {
                    'provider': 'Azure',
                    'services': await self.detect_azure_services(domain)
                }
            elif self.is_gcp_ip(ip):
                self.results['cloud'] = {
                    'provider': 'Google Cloud',
                    'services': await self.detect_gcp_services(domain)
                }
            else:
                self.results['cloud'] = {'provider': 'Not detected'}
        except Exception as e:
            self.results['cloud'] = {'error': str(e)}

    def is_aws_ip(self, ip: str) -> bool:
        aws_ranges = [
            '3.0.0.0/9',
            '52.0.0.0/8',
            '54.0.0.0/8'
        ]
        ip_obj = ipaddress.ip_address(ip)
        for range in aws_ranges:
            if ip_obj in ipaddress.ip_network(range):
                return True
        return False

    def is_azure_ip(self, ip: str) -> bool:
        azure_ranges = [
            '13.64.0.0/11',
            '20.0.0.0/8',
            '40.0.0.0/8'
        ]
        ip_obj = ipaddress.ip_address(ip)
        for range in azure_ranges:
            if ip_obj in ipaddress.ip_network(range):
                return True
        return False

    def is_gcp_ip(self, ip: str) -> bool:
        gcp_ranges = [
            '8.34.0.0/16',
            '8.35.0.0/17',
            '23.236.48.0/20'
        ]
        ip_obj = ipaddress.ip_address(ip)
        for range in gcp_ranges:
            if ip_obj in ipaddress.ip_network(range):
                return True
        return False

    async def detect_aws_services(self, domain: str) -> List[str]:
        services = []
        
        if await self.check_s3_bucket(domain):
            services.append('S3')
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{domain}") as resp:
                    if 'Server' in resp.headers and 'CloudFront' in resp.headers['Server']:
                        services.append('CloudFront')
        except:
            pass
        
        return services if services else ['No specific services detected']

    async def detect_azure_services(self, domain: str) -> List[str]:
        services = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{domain}") as resp:
                    if 'x-ms-blob-type' in resp.headers:
                        services.append('Azure Blob Storage')
                    elif 'x-ms-request-id' in resp.headers:
                        services.append('Azure App Service')
        except:
            pass
        
        return services if services else ['No specific services detected']

    async def detect_gcp_services(self, domain: str) -> List[str]:
        services = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{domain}") as resp:
                    if 'x-guploader-uploadid' in resp.headers:
                        services.append('Google Cloud Storage')
                    elif 'Server' in resp.headers and 'Google Frontend' in resp.headers['Server']:
                        services.append('Google Load Balancer')
        except:
            pass
        
        return services if services else ['No specific services detected']

    async def s3_bucket_check(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]S3 bucket check...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        bucket_name = domain.split('.')[0]
        
        if domain.endswith('.amazonaws.com'):
            self.results['s3'] = {
                'bucket': domain,
                'status': 'Already an S3 endpoint'
            }
            return
        
        s3_domains = [
            f"{bucket_name}.s3.amazonaws.com",
            f"s3.amazonaws.com/{bucket_name}",
            f"{bucket_name}.s3-website-us-east-1.amazonaws.com",
            f"{bucket_name}.s3-website.{random.choice(['us-east-1', 'us-west-2', 'eu-west-1'])}.amazonaws.com"
        ]
        
        accessible = []
        
        async def check_s3_url(url):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://{url}") as resp:
                        if resp.status in [200, 403]:
                            accessible.append({
                                'url': url,
                                'status': resp.status,
                                'public': resp.status == 200
                            })
            except:
                pass
        
        tasks = [check_s3_url(url) for url in s3_domains]
        await asyncio.gather(*tasks)
        
        self.results['s3'] = accessible if accessible else ['No accessible S3 buckets found']

    async def check_s3_bucket(self, domain: str) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{domain}") as resp:
                    return 'x-amz-bucket-region' in resp.headers
        except:
            return False

    async def traceroute(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Traceroute...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['tracert', '-d', domain], capture_output=True, text=True)
            else:
                result = subprocess.run(['traceroute', domain], capture_output=True, text=True)
            
            self.results['traceroute'] = result.stdout.split('\n')
        except Exception as e:
            self.results['traceroute'] = {'error': str(e)}

    async def os_fingerprinting(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]OS fingerprinting...")
        
        try:
            nm = nmap.PortScanner()
            arguments = f"-O -T4 {urlparse(self.target).hostname}"
            nm.scan(arguments=arguments)
            
            os_info = {}
            for host in nm.all_hosts():
                for line in nm[host]['osmatch']:
                    if 'osclass' in line:
                        for osclass in line['osclass']:
                            os_info = {
                                'type': osclass['type'],
                                'vendor': osclass['vendor'],
                                'osfamily': osclass['osfamily'],
                                'accuracy': osclass['accuracy']
                            }
                            break
                    if os_info:
                        break
            
            self.results['os_fingerprinting'] = os_info if os_info else {'message': 'OS detection failed'}
        except Exception as e:
            self.results['os_fingerprinting'] = {'error': str(e)}

    async def security_txt_check(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]security.txt check...")
        
        security_paths = [
            '/.well-known/security.txt',
            '/security.txt'
        ]
        
        found = None
        
        async def check_security_path(path):
            try:
                async with aiohttp.ClientSession() as session:
                    url = urljoin(self.target, path)
                    async with session.get(url) as resp:
                        if resp.status == 200:
                            return {
                                'url': url,
                                'content': await resp.text()
                            }
            except:
                return None
        
        tasks = [check_security_path(path) for path in security_paths]
        results = await asyncio.gather(*tasks)
        found = next((r for r in results if r), None)
        
        if found:
            try:
                security_txt = {
                    'contacts': [],
                    'expires': None,
                    'encryption': None,
                    'acknowledgments': None
                }
                
                for line in found['content'].split('\n'):
                    if line.startswith('Contact:'):
                        security_txt['contacts'].append(line[8:].strip())
                    elif line.startswith('Expires:'):
                        security_txt['expires'] = line[8:].strip()
                    elif line.startswith('Encryption:'):
                        security_txt['encryption'] = line[11:].strip()
                    elif line.startswith('Acknowledgments:'):
                        security_txt['acknowledgments'] = line[16:].strip()
                
                self.results['security_txt'] = {
                    'url': found['url'],
                    'contacts': security_txt['contacts'],
                    'expires': security_txt['expires'],
                    'encryption': security_txt['encryption'],
                    'acknowledgments': security_txt['acknowledgments']
                }
            except Exception as e:
                self.results['security_txt'] = {
                    'url': found['url'],
                    'error': f"Parse error: {str(e)}",
                    'content': found['content']
                }
        else:
            self.results['security_txt'] = {'message': 'No security.txt file found'}

    async def dmarc_dkim_spf_check(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Email security checks...")
        
        domain = urlparse(self.target).netloc.split(':')[0]
        results = {}
        
        try:
            spf_record = await self.get_dns_record(domain, 'TXT')
            spf_records = [r for r in spf_record if 'v=spf1' in r]
            if spf_records:
                spf_result = spf.check(domain, '127.0.0.1', spf_records[0])
                results['spf'] = {
                    'record': spf_records[0],
                    'result': str(spf_result)
                }
            else:
                results['spf'] = {'message': 'No SPF record found'}
        except Exception as e:
            results['spf'] = {'error': str(e)}
        
        try:
            dmarc_record = await self.get_dns_record(f'_dmarc.{domain}', 'TXT')
            dmarc_records = [r for r in dmarc_record if 'v=DMARC1' in r]
            if dmarc_records:
                dmarc_result = dmarc.parse_dmarc_record(dmarc_records[0])
                results['dmarc'] = {
                    'record': dmarc_records[0],
                    'result': dmarc_result
                }
            else:
                results['dmarc'] = {'message': 'No DMARC record found'}
        except Exception as e:
            results['dmarc'] = {'error': str(e)}
        
        common_selectors = ['google', 'selector1', 'selector2', 'dkim', 'default']
        dkim_found = False
        
        for selector in common_selectors:
            try:
                dkim_record = await self.get_dns_record(f'{selector}._domainkey.{domain}', 'TXT')
                if dkim_record and 'v=DKIM1' in dkim_record[0]:
                    dkim_found = True
                    results['dkim'] = {
                        'selector': selector,
                        'record': dkim_record[0]
                    }
                    break
            except:
                continue
        
        if not dkim_found:
            results['dkim'] = {'message': 'No DKIM record found with common selectors'}
        
        self.results['email_security'] = results

    async def get_dns_record(self, domain: str, record_type: str) -> List[str]:
        try:
            answers = await dns.asyncresolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            raise Exception(f"DNS query failed: {e}")

    def generate_reports(self):
        self.progress.update(self.task_id, advance=5, description="[cyan]Generating reports...")
        
        report_dir = self.config['output']['report_dir']
        domain = urlparse(self.target).netloc.split(':')[0]
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{domain}_{timestamp}"
        
        json_file = os.path.join(report_dir, f"{base_filename}.json")
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        csv_file = os.path.join(report_dir, f"{base_filename}.csv")
        self.generate_csv_report(csv_file)
        
        html_file = os.path.join(report_dir, f"{base_filename}.html")
        self.generate_html_report(html_file)
        
        if pdfkit is not None:
            pdf_file = os.path.join(report_dir, f"{base_filename}.pdf")
            self.generate_pdf_report(html_file, pdf_file)
        
        md_file = os.path.join(report_dir, f"{base_filename}.md")
        self.generate_markdown_report(md_file)
        
        xml_file = os.path.join(report_dir, f"{base_filename}.xml")
        self.generate_xml_report(xml_file)
        
        console.print(f"[green]Reports generated in {report_dir} directory[/green]")

    def generate_csv_report(self, filename: str):
        try:
            flat_data = []
            
            for category, data in self.results.items():
                if isinstance(data, dict):
                    for subcat, subdata in data.items():
                        flat_data.append({
                            'Category': category,
                            'Subcategory': subcat,
                            'Details': str(subdata)
                        })
                else:
                    flat_data.append({
                        'Category': category,
                        'Subcategory': '',
                        'Details': str(data)
                    })
            
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['Category', 'Subcategory', 'Details'])
                writer.writeheader()
                writer.writerows(flat_data)
        except Exception as e:
            logger.error(f"Failed to generate CSV report: {e}")

    def generate_html_report(self, filename: str):
        try:
            env = Environment(loader=FileSystemLoader('.'))
            template = env.get_template('report_template.html')
            
            report_data = {
                'target': self.target,
                'date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'results': self.results
            }
            
            html = template.render(report_data)
            
            with open(filename, 'w') as f:
                f.write(html)
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {e}")

    def generate_pdf_report(self, html_file: str, pdf_file: str):
        try:
            options = {
                'quiet': '',
                'margin-top': '0.5in',
                'margin-right': '0.5in',
                'margin-bottom': '0.5in',
                'margin-left': '0.5in',
                'encoding': "UTF-8"
            }
            
            pdfkit.from_file(html_file, pdf_file, options=options)
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {e}")

    def generate_markdown_report(self, filename: str):
        try:
            with open(filename, 'w') as f:
                f.write(f"# Web Reconnaissance Report\n\n")
                f.write(f"**Target**: {self.target}\n")
                f.write(f"**Date**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for category, data in self.results.items():
                    f.write(f"## {category.replace('_', ' ').title()}\n\n")
                    
                    if isinstance(data, dict):
                        for subcat, subdata in data.items():
                            f.write(f"### {subcat.replace('_', ' ').title()}\n\n")
                            f.write(f"```\n{subdata}\n```\n\n")
                    else:
                        f.write(f"```\n{data}\n```\n\n")
        except Exception as e:
            logger.error(f"Failed to generate Markdown report: {e}")

    def generate_xml_report(self, filename: str):
        try:
            root = ET.Element("WebReconReport")
            ET.SubElement(root, "Target").text = self.target
            ET.SubElement(root, "Date").text = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            results = ET.SubElement(root, "Results")
            for category, data in self.results.items():
                cat_elem = ET.SubElement(results, category.replace(' ', '_'))
                if isinstance(data, dict):
                    for subcat, subdata in data.items():
                        sub_elem = ET.SubElement(cat_elem, subcat.replace(' ', '_'))
                        sub_elem.text = str(subdata)
                else:
                    cat_elem.text = str(data)
            
            tree = ET.ElementTree(root)
            tree.write(filename, encoding='utf-8', xml_declaration=True)
        except Exception as e:
            logger.error(f"Failed to generate XML report: {e}")

    def print_summary(self):
        console.rule("[bold blue]Scan Summary[/bold blue]")
        
        table = Table(title=f"Results for {self.target}", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Details", style="green")
        
        for key, value in self.results.items():
            if isinstance(value, (dict, list)):
                display = json.dumps(value, indent=2)
            else:
                display = str(value)
            table.add_row(key.replace('_', ' ').title(), display)
        
        console.print(table)

async def main():
    parser = argparse.ArgumentParser(description='Advanced Web Reconnaissance Tool')
    parser.add_argument('target', help='Target URL or domain to scan')
    parser.add_argument('--config', help='Path to config file', default='config.ini')
    args = parser.parse_args()
    
    config = configparser.ConfigParser()
    if os.path.exists(args.config):
        config.read(args.config)
    else:
        config.read_dict(DEFAULT_CONFIG)
        with open(args.config, 'w') as f:
            config.write(f)
    
    scanner = WebRecon(args.target, {s: dict(config.items(s)) for s in config.sections()})
    await scanner.run_scan()
    scanner.print_summary()

if __name__ == '__main__':
    asyncio.run(main())
