# recon.py
Recon - A collection of an IP and Network Tools that can be used to quickly get information about IP Addresses, Web Pages, and DNS records.
```
 _  _   _  _   _ 
|  (/_ (_ (_) | |
```
Note: There is a 500 URLs limit per request for Google's SafeBrowsing lookup and 100 API requests per day from a single IP address for other tools lookup.

### Setting up an API KEY
To set up a Google's SafeBrwosing API key, see [Setting up API keys](https://cloud.google.com/docs/authentication/api-keys?hl=en&ref_topic=6262490&visit_id=1-636670504281135868-1002741086&rd=1#creating_an_api_key "Creating an API key").

Once created an API KEY, set a local environment variable as GSB_API_KEY with it.

```python
GSB_API_KEY = os.environ['GSB_API_KEY']
sburl = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + GSB_API_KEY
```

### Input file
Input file 'lookup_input.txt' should be:
 - a valid domain or subdomain or an URL
 - For example: example.com or downloads.example.com or https://</span>example.com/</span>downloads.html
 - a line separated
 - an unique inputs

### [-] DNS Queries
 1. Whois Lookup
 2. DNS Lookup
 3. Reverse DNS
 4. Find DNS Host (A) Records
 5. Find Shared DNS Servers
 6. Zone Transfer

### [-] IP Address

 7. Reverse IP Lookup
 8. GeoIP Lookup
 9. Nmap Scan
 10. Subnet Lookup

### [-] Network Tests

 11. Traceroute
 12. Test Ping

### [-] Web Tools

 13. HTTP Headers
 14. Extract Page Links
 
### [-] Malware Tools

 15. Google's SafeBrowsing
 
 
#d09r
