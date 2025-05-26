# WhoisToSplunk
This Python based application sends to Splunk domain registration information of domains visited on your network. Building an enriched database of information on domains in your network activity expands capability and vectors that can be used for threat hunting and analysis. 

# Spotting Evil With This Tool
A large majority of malicious domains were recently purchased, bought on cheaper and less reputable registrars (namecheap, namesilo, etc.), have anonomized contact information, an address that doesn't really exist, etc. All of that can be observed by analyzing the domain registration information. This tool provides you with the data you need to hunt for any of those suspicious attributes and more.

# How it works
This program runs within a docker container and requires the container to have ROOT or SUDO privilages for network interface access

Once ran it performs the following:
1. Listens to all traffic on a specified network interface (prompts the user to choose which interface is the monitor interface)
2. Captures only DNS requests and feeds them each to a multithreaded function to handle each domain seperately
##### DOMAIN CAPTURED -> NEW EXECUTION THREAD SPAWNED
3. Checks the local SQLLite database if the domain has been seen before
     IF YES: no action needed - thread terminates
     IF NO: Move on to step 4 below
4. Checks domain to ensure it is external, ruling out reverse lookups (arpa) or local domains
5. Performs a WHOIS (sends a WHOIS packet over the internet to obtain registration information)
6. Sanitizes the WHOIS data returned
7. Sends to WHOIS data as an event to Splunk via HEC over the loopback address

# Splunk Event Fields
domain_queried - (full domain string that was captured on the interface)

domain_name - (domain that WHOIS returned)
registrar  
registrar_url  
yearfirst  
dayfirst  
creation_date  
updated_date  
expiration_date  
name_servers  
status  
emails  
whois_server  
reseller  
dnssec  
name  
org  
address  
city  
state  
zipcode  
country  

## Known Issues
There can be occasional duplicate events in Splunk when a two larger subdomains return the same WHOIS information catagorized for the shared domain. For example two different domains of <random_characters>.azure.com may exist but both may just return the same WHOIS for azure.com. This isn't the case for all subdomains but I'm working to see which of these are edge cases and which are not. There is a fix by storing the WHOIS domains in the local database to check whether they exist prior to sending to Splunk, however this would increase the number of WHOIS requests which would not be ideal since the database check prior does lower the rate of WHOIS traffic required as the database grows.
