"""
SSL/TLS certificate analysis module.

Performs a TLS handshake against domain:443 and extracts certificate
details using the ssl, socket, and cryptography libraries.
"""

import ssl
import socket
import datetime
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def _rdn_sequence_to_dict(rdn_sequence):
    """Convert an RFC 4514 RelativeDistinguishedName tuple (as returned by
    SSLSocket.getpeercert) into a dict.  Each element of *rdn_sequence* is
    itself a tuple of (key, value) pairs; most certificates have a single
    pair per RDN but the format supports multiple, so we collect all of them
    keyed by OID short-name (e.g. 'commonName', 'organizationName')."""
    result = {}
    for rdn in rdn_sequence:
        for name, value in rdn:
            result[name] = value
    return result


def _parse_date(date_string):
    """Parse an ASN.1 UTC / generalized-time string from getpeercert.

    The format is ``Mon dd HH:MM:SS YYYY`` optionally followed by a space
    and a timezone abbreviation (e.g. ``GMT``).  ``strptime`` with ``%Z`` is
    not portable across platforms, so the timezone suffix is stripped before
    parsing.  The returned datetime is a naïve UTC datetime."""
    # Keep only the first four whitespace-delimited tokens (drop timezone abbr).
    stripped = ' '.join(date_string.split()[:4])
    return datetime.datetime.strptime(stripped, '%b %d %H:%M:%S %Y')


def _format_hex_colon(data: bytes) -> str:
    """Return a colon-separated, uppercase hex string for *data*."""
    return data.hex(':').upper()


def run_ssl(domain, ip=None):
    """Connect to *domain* on port 443 (optionally using *ip* to bypass DNS),
    perform a TLS handshake, and return a dict of certificate details.

    Returned keys:

    * **subject**          – dict of the certificate subject fields
    * **issuer**           – dict of the certificate issuer fields
    * **valid_from**       – ``datetime.datetime`` (UTC) the cert is valid from
    * **valid_to**         – ``datetime.datetime`` (UTC) the cert expires
    * **days_left**        – whole days until expiration (negative if expired)
    * **sans**             – list of Subject Alternative Names (strings)
    * **tls_version**      – TLS protocol version negotiated, e.g. ``TLSv1.3``
    * **cipher**           – cipher suite string, e.g.
                             ``TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=...``
    * **key_size**         – public-key size in bits (RSA modulus / EC curve)
    * **serial**           – certificate serial number (colon-hex)
    * **fingerprint_sha256** – SHA-256 fingerprint of the leaf cert
                               (colon-hex)
    * **is_valid**         – ``True`` when the certificate is currently valid
                             (notBefore <= now <= notAfter)
    * **chain**            – list of colon-hex SHA-256 fingerprints for every
                             certificate in the chain (leaf first)

    On any error the return value is ``{'error': '<message>'}``.
    """
    sock = None
    ssock = None

    try:
        # ------------------------------------------------------------------
        # 1. Create SSL context
        # ------------------------------------------------------------------
        context = ssl.create_default_context()

        # ------------------------------------------------------------------
        # 2. Connect raw socket (5 s timeout)
        # ------------------------------------------------------------------
        target = ip if ip else domain
        sock = socket.create_connection((target, 443), timeout=5)

        # ------------------------------------------------------------------
        # 3. Wrap with TLS, send SNI so virtual-hosting works
        # ------------------------------------------------------------------
        ssock = context.wrap_socket(sock, server_hostname=domain)

        # ------------------------------------------------------------------
        # 4. Retrieve certificate dict and DER binary
        # ------------------------------------------------------------------
        cert_dict = ssock.getpeercert()
        if not cert_dict:
            return {'error': 'Server presented no certificate'}

        der_cert = ssock.getpeercert(binary_form=True)
        if not der_cert:
            return {'error': 'Could not retrieve certificate in binary form'}

        # ------------------------------------------------------------------
        # 5. Parse validity dates
        # ------------------------------------------------------------------
        not_before_str = cert_dict.get('notBefore', '')
        not_after_str = cert_dict.get('notAfter', '')
        if not not_before_str or not not_after_str:
            return {'error': 'Certificate missing validity dates'}

        valid_from = _parse_date(not_before_str)
        valid_to = _parse_date(not_after_str)

        # ------------------------------------------------------------------
        # 6. days_left
        # ------------------------------------------------------------------
        now = datetime.datetime.utcnow()
        days_left = (valid_to - now).days

        # ------------------------------------------------------------------
        # Subject / Issuer
        # ------------------------------------------------------------------
        subject = _rdn_sequence_to_dict(cert_dict.get('subject', ()))
        issuer = _rdn_sequence_to_dict(cert_dict.get('issuer', ()))

        # ------------------------------------------------------------------
        # 7. Subject Alternative Names
        # ------------------------------------------------------------------
        sans = []
        for san_entry in cert_dict.get('subjectAltName', ()):
            # Each SAN entry is a two-element tuple: (type, value)
            sans.append(san_entry[1])

        # ------------------------------------------------------------------
        # 8. TLS version and cipher
        # ------------------------------------------------------------------
        tls_version = ssock.version() or 'unknown'
        cipher_tuple = ssock.cipher()  # (name, version, bits) or None
        cipher = (
            '{} {} bits={}'.format(*cipher_tuple)
            if cipher_tuple
            else 'unknown'
        )

        # ------------------------------------------------------------------
        # 9. Cryptography analysis: fingerprint, key size, serial, chain
        # ------------------------------------------------------------------
        x509_cert = x509.load_der_x509_certificate(der_cert, default_backend())

        # SHA-256 fingerprint of the leaf cert
        fingerprint_sha256 = _format_hex_colon(
            x509_cert.fingerprint(hashes.SHA256())
        )

        # Public-key size
        public_key = x509_cert.public_key()
        key_size = public_key.key_size

        # Serial number (show as colon-separated hex)
        serial_raw = x509_cert.serial_number
        # Convert to zero-padded hex string
        serial_hex = format(serial_raw, 'X')
        if len(serial_hex) % 2:
            serial_hex = '0' + serial_hex
        serial = _format_hex_colon(bytes.fromhex(serial_hex))

        # Validity check (notBefore *and* notAfter)
        is_valid = valid_from <= now <= valid_to

        # ------------------------------------------------------------------
        # 10. Certificate chain
        # ------------------------------------------------------------------
        chain = []
        try:
            # get_unverified_chain was added in Python 3.10
            if hasattr(ssock, 'get_unverified_chain'):
                chain_der_list = ssock.get_unverified_chain()
                for cert_der in chain_der_list:
                    c = x509.load_der_x509_certificate(
                        cert_der, default_backend()
                    )
                    chain.append(
                        _format_hex_colon(c.fingerprint(hashes.SHA256()))
                    )
            if not chain:
                # At minimum, include the leaf cert fingerprint
                chain.append(fingerprint_sha256)
        except Exception:
            chain.append(fingerprint_sha256)

        # ------------------------------------------------------------------
        return {
            'subject': subject,
            'issuer': issuer,
            'valid_from': valid_from,
            'valid_to': valid_to,
            'days_left': days_left,
            'sans': sans,
            'tls_version': tls_version,
            'cipher': cipher,
            'key_size': key_size,
            'serial': serial,
            'fingerprint_sha256': fingerprint_sha256,
            'is_valid': is_valid,
            'chain': chain,
        }

    except socket.timeout:
        return {'error': 'Connection timed out'}
    except socket.gaierror as exc:
        return {'error': f'DNS resolution failed: {exc}'}
    except ConnectionRefusedError:
        return {'error': 'Connection refused'}
    except OSError as exc:
        return {'error': f'Network error: {exc}'}
    except ssl.SSLError as exc:
        return {'error': f'SSL error: {exc}'}
    except ssl.CertificateError as exc:
        return {'error': f'Certificate validation error: {exc}'}
    except Exception as exc:
        return {'error': f'Unexpected error: {exc}'}
    finally:
        if ssock is not None:
            try:
                ssock.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except Exception:
                pass
