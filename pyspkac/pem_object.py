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

from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.base         import Asn1Item
from base64                   import encodestring as b64encode

class PEM_Object (object) :
    """ Object or part of it can be serialized in PEM format
    """

    def _as_pem (self, asn1val, header = None) :
        """ Create base64 encoded version of asn1val and wrap in in
            appropriate BEGIN/END lines for pem format. The BEGIN/END text
            differs for different asn1 values, so we specify this as
            "header". This is necessary since most constructors in
            M2Crypto don't seem to have a version that directly accepts
            ASN.1, so we generate the pem version here.
        """
        # Derived class might want to have default pem_header
        if header is None :
            header = self.pem_header
        if isinstance (asn1val, Asn1Item) :
            asn1val = der_encode (asn1val)
        v = b64encode (asn1val)
        return '-----BEGIN %s-----\n%s-----END %s-----\n' \
            % (header, v, header)
    # end def _as_pem
# end class PEM_Object
