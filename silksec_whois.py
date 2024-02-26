import whois
import concurrent.futures


def query_whois(domain):
    """
    Perform a WHOIS query for a single domain.

    Parameters:
        domain (str): The domain to query WHOIS information for.

    Returns:
        tuple: A tuple containing the domain and its WHOIS information or error.
    """
    try:
        w = whois.whois(domain)
        # Handling NoneType for iterable fields
        nameservers = list(w.name_servers) if w.name_servers else []
        emails = w.emails if w.emails else []
        print(domain)
        # Simplified WHOIS information extraction with NoneType handling
        whois_info = {
            'domain': domain,
            'registrar': w.registrar,
            'whois_server': w.whois_server,
            'creation_date': str(w.creation_date) if w.creation_date else None,
            'expiration_date': str(w.expiration_date) if w.expiration_date else None,
            'nameservers': nameservers,
            'status': w.status,
            'emails': emails,
            'country': w.country,
            'updated_date': str(w.updated_date) if w.updated_date else None
        }

        return (domain, whois_info)
    except Exception as e:
        return (domain, {'error': str(e)})


def whois_domain(domains):
    """
    Query WHOIS information for a list of domains using the whois library, handling 'NoneType' iterable cases,
    and improving runtime speed by using parallel execution.

    Parameters:
        domains (list): List of domains to query WHOIS information for.

    Returns:
        tuple: A tuple containing two dictionaries:
            1. A dictionary containing WHOIS information for each domain.
            2. A list of unresolved domains.
    """
    domain_data = {}
    unresolved_domains = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        # Map domain names to the query_whois function and execute in parallel
        future_to_domain = {executor.submit(query_whois, domain): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_to_domain):
            domain, result = future.result()
            if 'error' in result:
                unresolved_domains.append(domain)
            domain_data[domain] = result

    return domain_data, unresolved_domains


if __name__ == '__main__':
    domains = [
        'example.com',
        'example.org',
        'example.net',
        'example.biz',
        'example.com.au',
        'example.fr',
        'example.kr',
        'example.cn',
        'example.ru',
        'example.au',
    ]
    domain_info, unresolved_domains = whois_domain(domains)
    print("Resolved Domain Information:")
    for domain, info in domain_info.items():
        print(f"{domain}: {info}")
    print("\nUnresolved Domains:")
    print(unresolved_domains)
