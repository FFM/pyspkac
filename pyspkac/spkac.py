#!/usr/bin/python
# Copyright (C) 2013 Dr. Ralf Schlatterbeck Open Source Consulting.
# Reichergasse 131, A-3411 Weidling.
# Web: http://www.runtux.com Email: office@runtux.com
# All rights reserved
# ****************************************************************************
# This library is free software; you can redistribute it and/or modify
# it under the terms of the GNU Library General Public License as
# published by the Free Software Foundation; either version 2 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
# ****************************************************************************

import time

from M2Crypto                 import ASN1, X509, EVP, BIO, RSA, m2
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.codec.ber.encoder import BitStringEncoder
from pyasn1.type.base         import Asn1Item
from pyasn1.error             import PyAsn1Error
from pyasn1.type.univ         import OctetString, BitString
from base64                   import b64decode
from base64                   import encodestring as b64encode
from bitstring                import Bitstring

class SPKAC_Decode_Error (ValueError) :
    pass

class SPKAC (object) :
    """ Netscape SPKI/SPKAC data structure
        ASN.1 notation of this (see HTML-5 keygen docs)
        PublicKeyAndChallenge ::= SEQUENCE {
            spki SubjectPublicKeyInfo,
            challenge IA5STRING
        }
        SignedPublicKeyAndChallenge ::= SEQUENCE {
               publicKeyAndChallenge PublicKeyAndChallenge,
               signatureAlgorithm AlgorithmIdentifier,
               signature BIT STRING
        }
    """

    # Table of Object Identifiers for public key crypto
    # We directly store the module from which the load_pub_key_bio
    # routine can be used and the assignment method name.
    # Seems the message digest algo is also specified here (md5)
    signature_algorithms = \
        { (1, 2, 840, 113549, 1, 1, 4) : (RSA, 'assign_rsa', 'md5')
        }

    # May come in handy in the future.
    hash_algorithms = \
        { (1, 3, 14, 3, 2, 26) : 'sha1'
        }

    def __init__ (self, b64val, challenge = None) :
        """ This gets a base64 encoded value as returned by a browser
            when filling in a form with a keygen element.
            The optional challenge is the challenge string issued by the
            web server and is checked against the signed challenge value
            returned by the browser (inside the b64val).
            We generally return a SPKAC_Decode_Error in case something
            cannot be parsed.
        """
        try :
            seq, rest = der_decode (b64decode (b64val))
        except PyAsn1Error, e :
            raise SPKAC_Decode_Error, e
        if rest :
            raise SPKAC_Decode_Error, "Data after SPKAC value"
        assert len (seq)     == 3
        assert len (seq [0]) == 2
        assert len (seq [1]) == 2
        assert not seq [1][1]
        self.signed    = der_encode (seq [0])
        self.spki      = seq [0][0]
        self.challenge = seq [0][1]
        self.sig_algo  = tuple (seq [1][0])
        self.signature = Bitstring (seq [2]).as_string ()
        if challenge and challenge != self.challenge :
            msg = "Challenge doesn't match: got %s expect %s" \
                % (challenge, self.challenge)
            raise SPKAC_Decode_Error, msg
        self.pkey, self.hash = self._compute_public_key_ ()
        self.pkey.reset_context    (md = self.hash)
        self.pkey.verify_init      ()
        self.pkey.verify_update    (self.signed)
        r = self.pkey.verify_final (self.signature)
        if r < 0 :
            raise SPKAC_Decode_Error, "Error during signature verification"
        if r == 0 :
            raise SPKAC_Decode_Error, "Invalid signature"
        assert r == 1 # sig verified
        self.extensions = X509.X509_Extension_Stack ()
        self.subject    = X509.X509_Name            ()
    # end def __init__

    def gen_crt \
        (self, ca_pkey, ca_crt, serial, not_before = None, not_after = None) :
        """ Return as an X509 certificate.
            We do this because M2Crypto doesn't wrap the SPKAC data
            structures. So to generate a certificate we get the key
            of the CA and sign the certificate with it.
            Note that the caller will have to make sure to not generate
            duplicate sequence numbers.
            Note this will also set self.cert for later retrieval. In
            addition self.cert is returned.
            Default not_before is now.
            Default validity time of not_after isn't set is 1 year from
            now.
        """
        if not not_before :
            not_before = long (time.time ()) + time.timezone
        if not not_after :
            not_after  = not_before + 60 * 60 * 24 * 365
        nb        = ASN1.ASN1_UTCTIME ()
        nb.set_time                   (not_before)
        na        = ASN1.ASN1_UTCTIME ()
        na.set_time                   (not_after)

        # copy country and organisation from issuer cert
        issuer = ca_crt.get_subject ()
        if not self.subject.O :
            self.subject.O = issuer.O
        if not self.subject.C :
            self.subject.C = issuer.C

        self.cert = cert = X509.X509  ()
        cert.set_version              (2)
        cert.set_serial_number        (serial)
        cert.set_not_before           (nb)
        cert.set_not_after            (na)
        cert.set_pubkey               (self.pkey)
        cert.set_subject              (self.subject)
        cert.set_issuer               (issuer)
        for ext in self.extensions :
            cert.add_ext (ext)
        cert.sign                     (pkey = ca_pkey, md = 'sha1')
        assert cert.verify            (ca_pkey)
        assert not cert.check_ca      ()
        assert cert.check_purpose     (m2.X509_PURPOSE_SSL_SERVER, 0)
        assert cert.check_purpose     (m2.X509_PURPOSE_NS_SSL_SERVER, 0)
        assert cert.check_purpose     (m2.X509_PURPOSE_ANY, 0)   
        return cert
    # end def gen_crt

    def push_extension (self, ext) :
        """ Specify an X509 extension for export as CRT.
            X509 extensions are specified with X509.new_extension, e.g.
            >>> x = X509.new_extension ('subjectAltName', 'DNS:foo.example.com')
        """
        self.extensions.push (ext)
    # end def push_extension

    def set_email (self, email) :
        """ Set the email *and* CN (common name) on self.subject.
            Usually client certificates are used for authentication
            purposes only. If the user loses the certificate we want as
            little information as possible on the cert (as much as is
            needed for authentication). So we set CN and emailAddress on
            the certificate (and O and C are set from the issuer if not
            explicitly set). Other attributes should be set via our
            subject attribute directly.
        """
        self.subject.CN    = email
        self.subject.Email = email
    # end def set_email

    def _as_pem (self, asn1val, header = None) :
        """ Create base64 encoded version of asn1val and wrap in in
            appropriate BEGIN/END lines for pem format. The BEGIN/END text
            differs for different asn1 values, so we specify this as
            "header". This is necessary since most constructors in
            M2Crypto don't seem to have a version that directly accepts
            ASN.1, so we generate the pem version here.
        """
        # Future: we might want to have default header
        if header is None :
            header = self.header
        if isinstance (asn1val, Asn1Item) :
            asn1val = der_encode (asn1val)
        v = b64encode (asn1val)
        return '-----BEGIN %s-----\n%s-----END %s-----\n' \
            % (header, v, header)
    # end def _as_pem

    def _compute_public_key_ (self) :
        """ Compute the public key as a EVP.PKey object from the
            information in the SPKAC.
            Note that there doesn't seem to be a direct way (at least in
            M2Crypto) to directly obtain an EVP from just the public key
            ASN.1 data. So we have to find out the signature algorithm
            and create the appropriate public key object. Then this is
            put into the PKey.
            This currently only supports RSA keys -- seems only RSA is
            wrapped in M2Crypto *and* we've never seen something other
            than RSA returned from a keygen tag by a browser.
        """
        if self.sig_algo not in self.signature_algorithms :
            raise 
        buf = BIO.MemoryBuffer (self._as_pem (self.spki, 'PUBLIC KEY'))
        mod, asg, hash = self.signature_algorithms [self.sig_algo]
        # the following effectively does
        # rsa = RSA.load_pub_key_bio (buf)
        # pkey.assign_rsa (rsa)
        alg    = mod.load_pub_key_bio (buf)
        pkey   = EVP.PKey ()
        method = getattr (pkey, asg)
        method (alg)
        return pkey, hash
    # end def _compute_public_key_

# end class SPKAC

if __name__ == '__main__' :
    spkac_encoded = \
        'MIICZjCCAU4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDN+AmlpbsZ' \
        'T3KE/Jgy5UCmPSlxE/w8LKBZ/yZ/oIYe5LvdS3uirpgDgR4wqsLd08d5zjTClCEZ' \
        'oV3T/R4WfWJtkn5rZKToNdCOLIrPcLQ1A5p3XfNSJl+hJnYDbrRi+bHIUs5J8Nue' \
        'yEEiXjFQrixh3+qdfl9iXP6gmFXNjKBxmPGMnoYawFnQxv52pQn64nJRT6i/usN9' \
        'ZbrB6aZ1WuiZQegV20oFlXPP+WtUj4gKr+5nGwk4ZHJUUl/JRT/gpWisL6Pk2Zap' \
        'zgvv60AEjvrsN0CvoCRmHTV3Zi+0RnEkrJEcWQ9LVB7o0z4ihGdTk2f4YZ4CgoKw' \
        'R0RdS99AE0mXAgMBAAEWJld0UVdNcnF6QnFUdklaVG0tZzQ0SHNyMS1xY3pQRmlR' \
        'bHc1V3N3MA0GCSqGSIb3DQEBBAUAA4IBAQAbY09EjJAe6o1VTt8U0stlTUAMm/cG' \
        'x+J3WDleNNZOsfi3GCEdXFBAcnTkMIT7fKPnMjKT0SFsYRkWG/ZZNGEBM+yHSDZS' \
        'hI0LEP7Rz8hU1sVx+MXIlrte4vdubk7G/HULgUAJpdo8S0CJENKie7TPJOOlCz/K' \
        '+aC5o2SDRFJsAvRuv8JayHXAkwaxgrQCY7z2/5fsW2xrL4HoTUHDIPvocpq9gtYs' \
        'yYIzG8/oN9tu3crWCEKZNM0GbO4R4XS2o5t83OmomDmFEgd2I2W9v2F0MINgA0G5' \
        '4e39s6B8OJTJdzJdTQMgFOIVL3p/FNfLVJyZ231e5ZUgHoP7Wt7iQQvn'
    ca_key = """
-----BEGIN RSA PRIVATE KEY-----
MIHyAgEAAjEA2w2VogdUqjsFye83ziWmp4Ob2cSmI0qsCFUzTNBjGSzLLX+0Q5Bb
P/Ey53R1KoKVAgMBAAECMQDAJKRSIfgD8g3b2Xer3Z7XZTv5wuKwJjgtC7ldEEYj
gu8lBk6Q0uLKbnclhe6GcykCGQDul7tDtkSZyZinzKewZCutENEqoxojfvcCGQDr
COe/GXIfMTzfL4T+r4OeYMw94t/dy9MCGDdSf11n+ege0oK19Xv0/huW9qkIQJtS
aQIYaYBj1oorigjmFCEWh+RtJmi5BYaTitH1Ahh9h58+CAbYYP5MM+SePGQEOwt0
cW/clZs=
-----END RSA PRIVATE KEY-----
"""
    ca_crt = """
-----BEGIN CERTIFICATE-----
MIICZTCCAh+gAwIBAgIJAKo62Scuo5c4MA0GCSqGSIb3DQEBBQUAMGIxCzAJBgNV
BAYTAkFUMQwwCgYDVQQIEwNOT2UxETAPBgNVBAcTCFdlaWRsaW5nMRMwEQYDVQQK
EwpydW50dXguY29tMR0wGwYJKoZIhvcNAQkBFg5yc2NAcnVudHV4LmNvbTAeFw0x
MzAxMTIxOTU2NTlaFw0yMzAxMTAxOTU2NTlaMGIxCzAJBgNVBAYTAkFUMQwwCgYD
VQQIEwNOT2UxETAPBgNVBAcTCFdlaWRsaW5nMRMwEQYDVQQKEwpydW50dXguY29t
MR0wGwYJKoZIhvcNAQkBFg5yc2NAcnVudHV4LmNvbTBMMA0GCSqGSIb3DQEBAQUA
AzsAMDgCMQDbDZWiB1SqOwXJ7zfOJaang5vZxKYjSqwIVTNM0GMZLMstf7RDkFs/
8TLndHUqgpUCAwEAAaOBxzCBxDAdBgNVHQ4EFgQU6nGMGGuGmXSVJTOYwCjYHe3R
TyQwgZQGA1UdIwSBjDCBiYAU6nGMGGuGmXSVJTOYwCjYHe3RTyShZqRkMGIxCzAJ
BgNVBAYTAkFUMQwwCgYDVQQIEwNOT2UxETAPBgNVBAcTCFdlaWRsaW5nMRMwEQYD
VQQKEwpydW50dXguY29tMR0wGwYJKoZIhvcNAQkBFg5yc2NAcnVudHV4LmNvbYIJ
AKo62Scuo5c4MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADMQCZhspBqy23
wJVVLRzkApuJ+1ZntRCo05Nozkzd/h1rL+ZJ4rWms+jXoEmG1ASz8cI=
-----END CERTIFICATE-----
"""

    spkac = SPKAC (spkac_encoded)
    assert spkac.challenge == 'WtQWMrqzBqTvIZTm-g44Hsr1-qczPFiQlw5Wsw'
    pkey  = EVP.load_key_string   (ca_key)
    cert  = X509.load_cert_string (ca_crt)
    spkac.set_email ('testuser@example.com')
    pe = spkac.push_extension
    ne = X509.new_extension
    pe (ne ('basicConstraints', 'CA:FALSE', critical = True))
    ku = 'digitalSignature, keyEncipherment, keyAgreement'
    pe (ne ('keyUsage', ku, critical = True))
    pe (ne ('extendedKeyUsage', 'clientAuth, emailProtection, nsSGC'))
    print spkac.gen_crt (pkey, cert, 42).as_pem ()
