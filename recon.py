#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#title                  : recon.py
#description            : Recon is a collection of an IP and Network Tools that can be used to quickly get 							  information about IP Addresses, Web Pages, and DNS records.
#author                 : D09r                   
#date                   : 20180705
#version                : 0.0.9                   
#usage                  : python recon.py
#notes                  : There is a 500 URLs limit per request for Google's SafeBrowsing lookup and 100 API                           requests per day from a single IP address for other tools lookup.
#opensource             : https://github.com/d09r/recon                                                 
#======================================================================================================== 

from __future__ import print_function

try:
	import os
	import json
	import urllib
	import urllib2
	import urlparse
	import datetime
	import httplib
	import logging
except ImportError, e:
	print('"'+str(e)+'"' + " << Please install this module and try again!\n")
	print("The following list of python modules is required to run this script!")
	print("[0] os")
	print("[1] urllib")
	print("[2] urllib2")
	print("[3] urlparse")
	print("[4] httplib")
	print("[5] datetime")
	print("[6] logging")
	print("[QUIT]")
	raise SystemExit

__author__ = "D09r"
__copyright__ = "Copyright 2018, D09r"
__license__ = "GNU General Public License v3.0"
__date__ = "20180705"
__version__ = "0.0.9"
__maintainer__ = "D09r"
__email__ = "d09r@yahoo.com"
__status__ = "Production"

logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)

# create a file handler
handler = logging.FileHandler('lookup_results.log')
handler.setLevel(logging.ERROR)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)

def quit(do,o_file):
	try:
		if do == 'api_limit':
			os.remove(o_file)
			print("[X] You've exceeded the API request limit!")
		elif do == 'invalid_option':
			os.remove(o_file)
			print("[X] Oops! You have entered an invalid option. Please, try a valid option from the menu.")
		elif do == 'no_input':
			os.remove(o_file)
			print("[X] Input file 'lookup_input.txt' is empty!")
		elif do == 'quit':
			os.remove(o_file)
	except OSError:
		pass
	print("[QUIT]")
	raise SystemExit

# tld extraction
def tld(domain):
	from tldextract import extract
	tsd, td, ts = extract(domain)
	domain = td + '.' + ts
	return domain

# whois lookup
def whois(domain,o_file):
	try:
		domain = tld(domain)
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/whois/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n")
		print("[-] Retrieved result for " + domain)
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()

# reverse_ip lookup	
def dns(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/dnslookup/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def reversedns(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/reversedns/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()

def arecords(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/hostsearch/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def shareddns(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/findshareddns/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def zonetransfer(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/zonetransfer/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def reverseip(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/reverseiplookup/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def geoip(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/geoip/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def nmap(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/nmap/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def subnetcalc(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/subnetcalc/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def tracert(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/mtr/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def ping(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/nping/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def httpheaders(domain,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/httpheaders/?q=" + domain).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+domain+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + domain, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def pagelinks(url,o_file):
	try:
		f = open(o_file,"a+")
		resp = urllib2.urlopen("https://api.hackertarget.com/pagelinks/?q=" + url).read()
		if resp == "API count exceeded":
			quit('api_limit',o_file)
		f.write("****** "+url+" ******\n" + resp + "\n\n")
		print("[-] Retrieved result for " + url, end='')
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()
		
def gsb(url,o_file):
	try:
		GSB_API_KEY = os.environ['GSB_API_KEY']
		f = open(o_file,"a+")
		sfurl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GSB_API_KEY
		para_values = {"client":{"clientId":"recon.py","clientVersion":"0.0.4"},"threatInfo":{'threatTypes':["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION","THREAT_TYPE_UNSPECIFIED"],'platformTypes':['ALL_PLATFORMS'],'threatEntryTypes':['URL'],'threatEntries':[{"url":url}]}}
		data = json.dumps(para_values)
		req = urllib2.Request(sfurl, data, {'Content-Type': 'application/json; charset=utf-8'})
		resp = urllib2.urlopen(req)
		gsb_result = resp.read()
		print("[-] Retrieved result for %s" % url)
		isGsbMatch = "matches" in gsb_result
		if isGsbMatch is False:
			gsb_res_neg = "%s wasn't found on Google's Safe Browsing list. It doesn't mean that website is benign!" % url
			print(gsb_res_neg)
			f.write("****** %s ******\n %s \n\n" % (url, gsb_res_neg))
		else:
			print("GSB flagged: %s" % url)
			print(gsb_result)
			f.write("****** %s ******\n %s \n\n" % (url, gsb_result))
	except IOError:
		print("IOError: Can\'t find the file 'Lookup results' or access them.")
	except urllib2.HTTPError, e:
		print("HTTPError: " + str(e.code))
	except urllib2.URLError, e:
		print("URLError: " + str(e.reason))
	except httplib.HTTPException, e:
		print("HTTPException: " + str(e))
	except Exception:
		import traceback
		print("Generic Exception: " + traceback.format_exc())
	else:
		f.close()

		
def main():
	done = False
  	if done:
		return
	else:
		print(" _  _   _  _   _ ")
		print("|  (/_ (_ (_) | |")
		title = "\nRecon"
		print(title + " - A collection of an IP, Network and Malware tools that can be used to quickly get information about IP Addresses, Web Pages, and DNS records.\n\nNote: There is a limit of 500 domains per requests for GSB and 100 API requests per day for other tools from a single IP address.\n\nAre you looking for a Recon in GUI version?\n[Chrome] https://chrome.google.com/webstore/detail/lpfpoenklfncdgminmpdoomkbjaiolod\n[Firefox] https://addons.mozilla.org/en-US/firefox/addon/recon-ip-network-tools\n\nInput file 'lookup_input.txt' should be:\n - a valid domain or subdomain or an URL\n - For example: example.com or downloads.example.com or https://example.com/downloads.html\n - a line separated\n - an unique inputs\n")
		try:
			option = int(raw_input("[-] DNS Queries\n 1. Whois Lookup\n 2. DNS Lookup\n 3. Reverse DNS\n 4. Find DNS Host (A) Records\n 5. Find Shared DNS Servers\n 6. Zone Transfer\n\n[-] IP Address\n 7. Reverse IP Lookup\n 8. GeoIP Lookup\n 9. Nmap Scan\n 10. Subnet Lookup\n\n[-] Network Tests\n 11. Traceroute\n 12. Test Ping\n\n[-] Web Tools\n 13. HTTP Headers\n 14. Extract Page Links\n\n[-] Malware Tools\n 15. Google's SafeBrowsing\n\n 0. Quit\n\nChoose the option: "))
		except ValueError:
#			print('\033c')
			print("[X] Oops! You have entered an invalid option. Please, try a valid option from the menu.")
			print("[QUIT]")
			raise SystemExit
		num_lines = 0
		try:
			f2 = open('lookup_input.txt', 'r') #input file
			if os.stat('lookup_input.txt').st_size == 0:
				print('\033c')
				print("[X] Input file 'lookup_input.txt' is empty!")
				print("[QUIT]")
				raise SystemExit
			else:
				# create an output file
				now = datetime.datetime.now()
				o_file = "Lookup results " + str(now) + ".txt"
				f1 = open(o_file,"w")
				f1.close()
			while True:
				url = f2.readline()
				if not url:
					break
				if url == " ":
					print("[X] There is an invalid input on line "+str(num_lines))
					continue
				domain = urlparse.urlsplit(url).netloc
				if not domain:
					domain = url.split('/')[0]
				if option == 1:
					whois(domain,o_file)
				elif option == 2:
					dns(domain,o_file)
				elif option == 3:
					reversedns(domain,o_file)
				elif option == 4:
					arecords(domain,o_file)
				elif option == 5:
					shareddns(domain,o_file)
				elif option == 6:
					zonetransfer(domain,o_file)
				elif option == 7:
					reverseip(domain,o_file)
				elif option == 8:
					geoip(domain,o_file)
				elif option == 9:
					nmap(domain,o_file)
				elif option == 10:
					subnetcalc(domain,o_file)
				elif option == 11:
					tracert(domain,o_file)
				elif option == 12:
					ping(domain,o_file)
				elif option == 13:
					httpheaders(domain,o_file)
				elif option == 14:
					pagelinks(url,o_file)
				elif option == 15:
					gsb(url,o_file)
				elif option == 0:
					quit('quit',o_file)
				elif str(option):
					quit('invalid_option',o_file)
				else:
					quit('invalid_option',o_file)

				num_lines += 1
		except IOError:
			print('\033c')
			print("IOError: Can\'t locate the input file 'lookup_input.txt' or read that. Please make sure it available in the current folder and have read access!")
			print("[QUIT]")
			raise SystemExit
		else:
			f2.close()
		if not num_lines:
			quit('no_input',o_file)
		f = open(o_file,"a+")
		f.write("\nTotal number of domains/IPs lookup: " + str(num_lines))
		print("\nTotal number of domains/IPs lookup: " + str(num_lines))
		print("Results updated in the file '" +o_file+"'")
		f.close()

if __name__ == "__main__":
	main()