import whois

def get_domain_registration_info(domain):
    try:
        w = whois.whois(domain)
        
        def format_first_date(date_field):
            if isinstance(date_field, list):
                # pick the first non-None date, else None
                first_date = next((d for d in date_field if d is not None), None)
                if first_date is not None:
                    return first_date.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    return None
            elif date_field is not None:
                return date_field.strftime("%Y-%m-%d %H:%M:%S")
            else:
                return None
        
        w.creation_date = format_first_date(w.creation_date)
        w.updated_date = format_first_date(w.updated_date)
        w.expiration_date = format_first_date(w.expiration_date)

        return {
            "domain_queried": domain,
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "registrar_url": w.registrar_url,
            "yearfirst": w.yearfirst,
            "dayfirst": w.dayfirst,
            "creation_date": w.creation_date,
            "updated_date": w.updated_date,
            "expiration_date": w.expiration_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "whois_server": w.whois_server,
            "reseller": w.reseller,
            "dnssec": w.dnssec,
            "name": w.name,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country
        }
    except Exception as e:
        if e.args[0].startswith("No match") is False:
            print(f"Error querying WHOIS for {domain}: {e}\n")
        return None

