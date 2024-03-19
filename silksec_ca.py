import ssl
import socket
from OpenSSL import crypto
import json

def parse_certificate_info(cert_bin):
    """
    Parses binary certificate information and extracts relevant details.

    Parameters:
        cert_bin (bytes): Binary certificate information.

    Returns:
        dict: Parsed certificate information.
    """
    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
    cert_info = {
        "Common Name": x509.get_subject().CN,
        "Organization": x509.get_subject().O or 'None',
        "Organizational Unit": x509.get_subject().OU or 'None',
        "Serial Number": '{0:x}'.format(x509.get_serial_number()).zfill(32),
        "Issuer Common Name": x509.get_issuer().CN,
        "Issuer Organization": x509.get_issuer().O or 'None',
        "Issuer Organizational Unit": x509.get_issuer().OU or 'None',
        "Not Before": x509.get_notBefore().decode('utf-8'),
        "Not After": x509.get_notAfter().decode('utf-8'),
        "Public Key": crypto.dump_publickey(crypto.FILETYPE_PEM, x509.get_pubkey()).decode('utf-8'),
        "Signature Algorithm": x509.get_signature_algorithm().decode('utf-8'),
        "Version": x509.get_version() + 1,
        "SHA-1 Fingerprint": x509.digest('sha1').decode('utf-8'),
        "SHA-256 Fingerprint": x509.digest('sha256').decode('utf-8'),
        "Extended Key Usage": None,
        "Key Usage": None,
        "Subject Alternative Name": []
    }

    # Extend
    for i in range(x509.get_extension_count()):
        ext = x509.get_extension(i)
        short_name = ext.get_short_name()
        if short_name == b'extendedKeyUsage':
            cert_info["Extended Key Usage"] = ext.__str__()
        elif short_name == b'keyUsage':
            cert_info["Key Usage"] = ext.__str__()
        elif short_name == b'subjectAltName':
            san_list = [san_value.strip() for san_value in str(ext).split(",")]
            cert_info["Subject Alternative Name"] = san_list

    return cert_info

def get_tls_info(domain):
    """
    Connects to a server and retrieves TLS certificate information.

    Parameters:
        domain (str): The domain name to connect to.

    Returns:
        dict: The parsed certificate information.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((domain, 443))
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    s = context.wrap_socket(s, server_hostname=domain)
    cert_bin = s.getpeercert(True)
    s.close()

    cert_info = parse_certificate_info(cert_bin)
    return cert_info

if __name__ == '__main__':
    domain = 'google.com'
    cert_info = get_tls_info(domain)
    print(json.dumps(cert_info, indent=4))
