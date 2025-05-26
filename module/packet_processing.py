from scapy.all import sniff, DNSQR, IP, get_if_list
import threading
import sqlite3

from module.whois_query import get_domain_registration_info
from module.send_to_splunk import send_to_splunk

# Buffer to store domains temporarily before writing
domain_buffer = set()
buffer_lock = threading.Lock()

def process_packet(packet):
    if packet.haslayer(DNSQR):  # DNS Query layer
        domain = packet[DNSQR].qname.decode().rstrip('.')
        with buffer_lock:
            if domain not in domain_buffer:
                domain_buffer.add(domain)
                # print(f"Captured domain: {domain}")
                
                if is_regular_domain(domain):
                    ## Store the domain in the database
                    if domain_exists(domain) is False:
                        if store_domain(domain):
                            # print(f"Stored new domain: {domain}")
                            whois_data = get_domain_registration_info(domain)
                            if whois_data is not None:
                                splunk_response = send_to_splunk(whois_data)
                                if splunk_response.status_code != 200:
                                    print("ERROR - Status Code: {splunk_response.status_code} for {domain}")
                else:
                    print(f"Skipping irregular domain: {domain}")                            

# Connect to SQLite database (creates file if it doesn't exist)
conn = sqlite3.connect('dns_queries.db')
cursor = conn.cursor()

# Create table if not exists
cursor.execute('''
    CREATE TABLE IF NOT EXISTS domains (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        domain TEXT UNIQUE
    )
''')
conn.commit()

def store_domain(domain):
    try:
        cursor.execute('INSERT INTO domains (domain) VALUES (?)', (domain,))
        conn.commit()
        # print(f"New domain stored: {domain}")
        return True
    except sqlite3.IntegrityError:
        print(f"ERROR - Domain already exists: {domain}")
        return False

def domain_exists(domain):
    cursor.execute("SELECT 1 FROM domains WHERE domain = ? LIMIT 1", (domain,))
    return cursor.fetchone() is not None

def is_regular_domain(domain):
    """
    Returns True if the domain is a regular, internet-facing domain.
    Returns False for irregular or reserved domains like localhost or reverse DNS.
    """
    if not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    # Common irregular domains
    irregular_domains = ["localhost", "localdomain"]
    for irregular in irregular_domains:
        if domain.endswith(irregular):
            return False

    # Check for reverse DNS and non-routable domains
    if domain.endswith(".arpa"):
        return False

    # Optionally: check if the domain contains a TLD
    elif "." not in domain or domain.endswith("."):
        return False
    else:
        return True
