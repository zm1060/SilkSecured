import subprocess
import concurrent.futures

def nslookup_command(domain, ns):
    """
    Executes the nslookup command for a given domain and nameserver.
    """
    result = subprocess.run(['nslookup', domain, ns], capture_output=True, text=True)
    if result.returncode == 0:
        return ns, result.stdout
    else:
        return ns, 'Failed to retrieve information'

def process_nslookup_results(domain, output):
    """
    Processes the output of an nslookup command, extracting relevant information.
    """
    lines = output.splitlines()
    current_entry = {'Name': '', 'Addresses': [], 'Aliases': []}

    for i in range(len(lines)):
        if lines[i].startswith('名称:') or lines[i].startswith('Name:'):
            current_entry = {'Name': lines[i].split(':')[1].strip(), 'Addresses': [], 'Aliases': []}
        elif lines[i].startswith('Addresses:') or lines[i].startswith('Address:'):
            addresses = extract_addresses(lines, i)
            current_entry['Addresses'].extend(addresses)
        elif lines[i].startswith('Aliases:'):
            aliases = extract_aliases(lines, i)
            current_entry['Aliases'].extend(aliases)

    return domain, current_entry

def nslookup_domain(domains, nameservers, group_by_domain=True):
    """
    Performs nslookup for the given domains using specified nameservers in parallel.
    """
    result_info = {}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Prepare a list of all tasks
        tasks = [(domain, ns) for domain in domains for ns in nameservers]

        # Start the load operations and mark each future with its domain
        future_to_nslookup = {executor.submit(nslookup_command, domain, ns): (domain, ns) for domain, ns in tasks}

        for future in concurrent.futures.as_completed(future_to_nslookup):
            domain, ns = future_to_nslookup[future]
            try:
                ns, output = future.result()
                if output != 'Failed to retrieve information':
                    _, result = process_nslookup_results(domain, output)
                    if group_by_domain:
                        if domain not in result_info:
                            result_info[domain] = {}
                        result_info[domain][ns] = result
                    else:
                        if ns not in result_info:
                            result_info[ns] = {}
                        result_info[ns][domain] = result
                else:
                    if group_by_domain:
                        if domain not in result_info:
                            result_info[domain] = {}
                        result_info[domain][ns] = {'error': 'Failed to retrieve information from the specified nameserver'}
                    else:
                        if ns not in result_info:
                            result_info[ns] = {}
                        result_info[ns][domain] = {'error': 'Failed to retrieve information'}
            except Exception as exc:
                print(f'{domain} generated an exception: {exc}')

    return result_info

def extract_addresses(lines, start_index):
    """
    Extracts addresses from the lines starting from the given index.

    Parameters:
        lines (list): List of lines to extract addresses from.
        start_index (int): The starting index to begin extraction.

    Returns:
        list: List of extracted addresses.
    """
    addresses = []
    for i in range(start_index, len(lines)):
        if lines[i].startswith('Addresses:'):
            address_part = lines[i].split('Addresses:')[1].strip()
            addresses.extend(addr.strip() for addr in address_part.split())
        elif lines[i].startswith('Address:'):
            address_part = lines[i].split('Address:')[1].strip()
            addresses.extend(addr.strip() for addr in address_part.split())
        elif lines[i].startswith((' ', '\t')):
            addresses.extend(addr.strip() for addr in lines[i].split())
        elif lines[i].startswith(('Name:', 'Aliases:')):
            break
    return addresses


def extract_aliases(lines, start_index):
    """
    Extracts aliases from the lines starting from the given index.

    Parameters:
        lines (list): List of lines to extract aliases from.
        start_index (int): The starting index to begin extraction.

    Returns:
        list: List of extracted aliases.
    """
    aliases = []
    for i in range(start_index, len(lines)):
        if lines[i].startswith('Aliases:'):
            aliases_part = lines[i].split('Aliases:')[1].strip()
            aliases.extend(addr.strip() for addr in aliases_part.split(','))
        elif lines[i].startswith((' ', '\t')):
            aliases.extend(addr.strip() for addr in lines[i].split(','))
        elif lines[i].startswith(('Name:', 'Addresses:', 'Address')) or lines[i].strip() == '':
            break
    return aliases


if __name__ == '__main__':
    domains = ['www.baidu.com', 'www.google.com']
    servers = ['114.114.114.114', '223.5.5.5', '8.8.8.8', '8.8.4.4', '1.1.1.1']

    # Group by domain
    result_by_domain = nslookup_domain(domains, servers, group_by_domain=True)
    print("Results grouped by domain:")
    print(result_by_domain)

    # Group by nameserver
    result_by_server = nslookup_domain(domains, servers, group_by_domain=False)
    print("\nResults grouped by nameserver:")
    print(result_by_server)
