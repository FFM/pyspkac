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

from time                     import time, gmtime, strftime
from M2Crypto                 import X509, EVP
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ         import BitString, Sequence, ObjectIdentifier
from pyasn1.type.univ         import Integer, Null
from pyasn1.type.useful       import UTCTime
from pyspkac.pem_object       import PEM_Object

class CRL (PEM_Object) :
    """ Model a Certificate Revocation List
        >>> import test
        >>> cert = X509.load_cert_string (test.ca_crt)
        >>> key  = EVP.load_key_string   (test.ca_key)
        >>> crl  = CRL (cert.get_subject (), 1358283817)
        >>> crl.append (   4, 1281729979)
        >>> crl.append (4711, 1358281992)
        >>> print crl.as_pem (key).strip ()
        -----BEGIN X509 CRL-----
        MIIBATCBvDANBgkqhkiG9w0BAQQFADBiMQswCQYDVQQGEwJBVDEMMAoGA1UECBMDTk9lMREwDwYD
        VQQHEwhXZWlkbGluZzETMBEGA1UEChMKcnVudHV4LmNvbTEdMBsGCSqGSIb3DQEJARYOcnNjQHJ1
        bnR1eC5jb20XDTEzMDExNTIxMDMzN1oXDTEzMDIxNTIxMDMzN1owKTASAgEEFw0xMDA4MTMyMDA2
        MTlaMBMCAhJnFw0xMzAxMTUyMDMzMTJaMA0GCSqGSIb3DQEBBAUAAzEAobLmqYztu5vXBcUlW5o8
        5N9EZnkISJkx5mF/h+Mja83AuA8GtGQXPrmGnztB5QiI
        -----END X509 CRL-----
    """

    pem_header = 'X509 CRL'
    time_fmt   = "%y%m%d%H%M%SZ"

    crl_oid = (1, 2, 840, 113549, 1, 1, 4)
    
    def __init__ (self, subject, last_update = None, next_update = None) :
        self.asn1_subject, rest = der_decode (subject.as_der ())
        assert not rest
        self.crl = []
        lu = last_update or long (time ())
        nu = next_update or lu + 60 * 60 * 24 * 31
        self.last_update = UTCTime (strftime (self.time_fmt, gmtime (lu)))
        self.next_update = UTCTime (strftime (self.time_fmt, gmtime (nu)))
    # end def __init__

    def append (self, serial, date) :
        """ Append serial to the revocation list with the given
            revocation date.
        """
        self.crl.append ((serial, date))
    # end def append

    def as_der (self, key) :
        """ Serialize CRL in DER format.
        """
        x = self._as_asn1 (key)
        return der_encode (x)
    # end def as_der

    def as_pem (self, key) :
        """ Serialize CRL in PEM format.
        """
        d = self.as_der (key)
        return self._as_pem (d)
    # end def as_pem

    def _as_asn1 (self, key) :
        asn1_crl   = Sequence ()
        asn1_inner = Sequence ()
        asn1_crl.setComponentByPosition (0, asn1_inner)
        id = Sequence ()
        id.setComponentByPosition (0, ObjectIdentifier (self.crl_oid))
        id.setComponentByPosition (1, Null ())
        asn1_inner.setComponentByPosition (0, id)
        asn1_crl.setComponentByPosition   (1, id)
        asn1_inner.setComponentByPosition (1, self.asn1_subject)
        asn1_inner.setComponentByPosition (2, self.last_update)
        asn1_inner.setComponentByPosition (3, self.next_update)
        seq = Sequence ()
        for n, (serial, date) in enumerate (self.crl) :
            entry = Sequence ()
            entry.setComponentByPosition (0, Integer (serial))
            d = strftime (self.time_fmt, gmtime (date))
            entry.setComponentByPosition (1, UTCTime (d))
            seq.setComponentByPosition (n, entry)
        asn1_inner.setComponentByPosition (4, seq)
        der_inner = der_encode (asn1_inner)
        key.reset_context (md = 'md5')
        key.sign_init ()
        key.sign_update (der_inner)
        sig = key.sign_final ()
        sig = BitString ("'%s'H" % ''.join ("%02X" % ord (c) for c in sig))
        asn1_crl.setComponentByPosition (2, sig)
        return asn1_crl
    # end def _as_asn1

# end class CRL
