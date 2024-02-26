# SilkSecured
SilkSecured Toolbox


## Function: nslookup_domain

### Description:
Performs nslookup for the given domains using specified nameservers.

### Parameters:
- `domains` (list): List of domains to perform nslookup on.
- `nameservers` (list): List of DNS servers to query.
- `group_by_domain` (bool, optional): If True, results will be grouped by domain. If False, results will be grouped by nameserver. Default is True.

### Returns:
- `dict`: A dictionary containing information extracted from nslookup.
  - Keys are either domains or nameservers based on the `group_by_domain` parameter.
  - Values are dictionaries containing nslookup information for each domain or nameserver.

### Example Usage:
```python
import silksec_nslookup
domains = ['www.baidu.com', 'www.google.com']
servers = ['114.114.114.114', '223.5.5.5', '8.8.8.8', '8.8.4.4', '1.1.1.1']

# Group by domain
result_by_domain = silksec_nslookup.nslookup_domain(domains, servers, group_by_domain=True)
print("Results grouped by domain:")
print(result_by_domain)

# Group by nameserver
result_by_server = silksec_nslookup.nslookup_domain(domains, servers, group_by_domain=False)
print("\nResults grouped by nameserver:")
print(result_by_server)
```


## Function: whois_domain

### Description:
Queries WHOIS information for a list of domains in parallel, handling 'NoneType' iterable cases and potential errors gracefully. This function improves efficiency by utilizing concurrent execution and provides detailed WHOIS information for each queried domain.

### Parameters:
- `domains` (list): List of domain names to query WHOIS information for.

### Returns:
- `tuple`: A tuple containing two elements:
  - **First Element** (`dict`): A dictionary with domain names as keys and their WHOIS information as values. If an error occurs during a query, the value will be another dictionary containing an `'error'` key with the corresponding error message as its value.
  - **Second Element** (`list`): A list of domain names for which the WHOIS query was unsuccessful or could not be resolved.

### Example Usage:
```python
import silksec_whois
domains = [
    'example.com',
    'example.org',
    'example.net',
    'example.biz',
    'example.co.uk',
    'example.com.au',
    'example.fr',
    'example.kr',
    'example.cn',
    'example.ru',
    'example.au',
]

domain_info, unresolved_domains = silksec_whois.whois_domain(domains)
print("Resolved Domain Information:")
for domain, info in domain_info.items():
    print(f"{domain}: {info}")
print("\\nUnresolved Domains:")
print(unresolved_domains)
```


## Function: get_tls_info

### Description:
Tests the TLS version and retrieves certificate information of a server specified by its hostname or IP address. This function provides detailed TLS information including version, certificate details, cipher, hostname, and FQDN match status.

### Parameters:
- `host` (str): Hostname or IP address of the server.
- `port` (int): Port number to use for the connection. Default is 443.

### Returns:
- `dict`: A dictionary containing TLS information for the specified server.
  - **'TLS_Version'** (`str`): The TLS version used for the connection.
  - **'Certificate_Info'** (`dict`): Parsed certificate information. See below for details.
  - **'Cipher'** (`str`): The cipher used for the connection.
  - **'Host'** (`str`): The hostname or IP address of the server.
  - **'FQDN_Match'** (`bool`): Indicates whether the certificate's common name or any Subject Alternative Name (SAN) matches the actual hostname.

  The **'Certificate_Info'** dictionary contains the following fields:
  - **'Subject_Country'** (`str`): The country name of the subject.
  - **'Subject_State'** (`str`): The state or province name of the subject.
  - **'Subject_Locality'** (`str`): The locality or city name of the subject.
  - **'Subject_Organization'** (`str`): The organization name of the subject.
  - **'Subject_CommonName'** (`str`): The common name (CN) of the subject.
  - **'SubjectAltName'** (`list` of `str`): A list of Subject Alternative Names (SANs) of the certificate.
  - **'NotBefore'** (`str`): The validity period start date of the certificate.
  - **'NotAfter'** (`str`): The validity period end date of the certificate.

  If an error occurs during the execution of the function, the returned dictionary will contain the following additional field:
  - **'Error'** (`str`): A string describing the encountered error.

### Example Usage:
```python
import silksec_ca

print(silksec_ca.get_tls_info('www.example.com'))
# Output:
# {
#     'TLS_Version': 'TLSv1.2',
#     'Certificate_Info': {
#         'Subject_Country': 'US',
#         'Subject_State': 'California',
#         'Subject_Locality': 'Mountain View',
#         'Subject_Organization': 'Example Inc.',
#         'Subject_CommonName': 'www.example.com',
#         'SubjectAltName': ['www.example.com', 'example.com'],
#         'NotBefore': 'Jan  1 00:00:00 2023 GMT',
#         'NotAfter': 'Jan  1 00:00:00 2024 GMT'
#     },
#     'Cipher': 'ECDHE-RSA-AES256-GCM-SHA384',
#     'Host': 'www.example.com',
#     'FQDN_Match': True
# }
```


