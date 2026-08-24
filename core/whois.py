import whois

def get_whois(domain):
    try:
        data = whois.whois(domain)
        return {
            "registrar": data.registrar,
            "creation_date": str(data.creation_date),
            "expiration_date": str(data.expiration_date)
        }
    except Exception as e:
        return {"error": str(e)}
