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

from pyasn1.codec.ber.encoder import BitStringEncoder
from pyasn1.type.univ         import BitString

class Bitstring (BitString) :
    """ Extend pyasn1 BitString to allow output as string.
        We're using pyasn1 own serialisation for this.
        Note that result is quite undefined if the number of bits isn't
        divisible by 8. This is usually not the case for signatures etc.
    """

    def as_string (self) :
        enc = BitStringEncoder ()
        z = enc._encodeValue (None, self, None, None)
        return z [0][1:]
    # end def as_string

# end class Bitstring
