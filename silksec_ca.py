import ssl
import socket
import fnmatch


def parse_certificate_info(cert_info):
    """
    Parses certificate information and extracts relevant details.

    Parameters:
        cert_info (dict): Dictionary containing certificate information.

    Returns:
        dict: Parsed certificate information.
    """
    parsed_info = {}

    # Extract subject details
    subject = cert_info.get('subject', [])
    for attr_list in subject:
        for attr, value in attr_list:
            if attr == 'countryName':
                parsed_info['Subject_Country'] = value
            elif attr == 'stateOrProvinceName':
                parsed_info['Subject_State'] = value
            elif attr == 'localityName':
                parsed_info['Subject_Locality'] = value
            elif attr == 'organizationName':
                parsed_info['Subject_Organization'] = value
            elif attr == 'commonName':
                parsed_info['Subject_CommonName'] = value

    # Extract issuer details
    issuer = cert_info.get('issuer', [])
    for attr_list in issuer:
        for attr, value in attr_list:
            if attr == 'countryName':
                parsed_info['Issuer_Country'] = value
            elif attr == 'organizationName':
                parsed_info['Issuer_Organization'] = value
            elif attr == 'commonName':
                parsed_info['Issuer_CommonName'] = value

    # Extract subjectAltName
    subject_alt_name = cert_info.get('subjectAltName', [])
    parsed_info['SubjectAltName'] = [value for _, value in subject_alt_name] if subject_alt_name else None

    # Extract notBefore and notAfter
    parsed_info['NotBefore'] = cert_info.get('notBefore', '')
    parsed_info['NotAfter'] = cert_info.get('notAfter', '')

    return parsed_info


def fqdn_match(host, cert_info):
    """
    Checks if the host matches any of the subject alternative names or common name in the certificate.

    Parameters:
        host (str): The hostname to check.
        cert_info (dict): The certificate information.

    Returns:
        bool: True if there's a match, False otherwise.
    """
    san = cert_info.get('subjectAltName', [])
    for entry in san:
        _, san_host = entry
        if fnmatch.fnmatch(host, san_host):
            return True

    # Fallback to common name if SAN is not available or no match found
    cn = next((val for ((attr, val),) in cert_info.get('subject', []) if attr == 'commonName'), None)
    if cn and fnmatch.fnmatch(host, cn):
        return True

    return False


def get_tls_info(host, port=443):
    """
    Tests the TLS version and retrieves certificate information of a server.

    Parameters:
        host (str): Hostname or IP address of the server.
        port (int): Port number. Default is 443.

    Returns:
        dict: Dictionary containing TLS information including version, certificate, cipher, host, and FQDN match.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cert_info = ssock.getpeercert()
                cipher = ssock.cipher()

                # Check if the common name or any SAN matches the actual hostname
                fqdn_match_result = fqdn_match(host, cert_info)

                return {
                    'TLS_Version': tls_version,
                    'Certificate_Info': parse_certificate_info(cert_info),
                    'Cipher': cipher,
                    'Host': host,
                    'FQDN_Match': fqdn_match_result
                }

    except Exception as e:
        return {
            'TLS_Version': None,
            'Certificate_Info': None,
            'Cipher': None,
            'Host': host,
            'FQDN_Match': False,
            'Error': str(e)
        }


if __name__ == '__main__':
    print(get_tls_info('www.baidu.com'))
