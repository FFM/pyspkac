from M2Crypto                 import X509, EVP, BIO, RSA
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.base         import Asn1Item
from pyasn1.error             import PyAsn1Error
from base64                   import b64decode
from base64                   import encodestring as b64encode

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
    signature_algorithms = \
        { (1, 2, 840, 113549, 1, 1, 4) : (RSA, 'assign_rsa')
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
        self.spki      = seq [0][0]
        self.challenge = seq [0][1]
        self.sig_algo  = tuple (seq [1][0])
        self.signature = seq [2]
        if challenge and challenge != self.challenge :
            msg = "Challenge doesn't match: got %s expect %s" \
                % (challenge, self.challenge)
            raise SPKAC_Decode_Error, msg
        self.pkey      = self._compute_public_key_ ()
    # end def __init__

    def _as_pem (self, asn1val, header = None) :
        """ Create base64 encoded version of asn1val and wrap in in
            appropriate BEGIN/END lines for pem format. The BEGIN/END text
            differs for different asn1 values, so we specify this as
            "header". This is necessary since most constructors in
            M2Crypto don't seem to have a version that directly accepts
            ASN.1, so we generate the pem version here.
        """
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
        buf      = BIO.MemoryBuffer (self._as_pem (self.spki, 'PUBLIC KEY'))
        mod, asg = self.signature_algorithms [self.sig_algo]
        # the following effectively does
        # rsa = RSA.load_pub_key_bio (buf)
        # pkey.assign_rsa (rsa)
        alg      = mod.load_pub_key_bio (buf)
        pkey     = EVP.PKey ()
        method   = getattr (pkey, asg)
        method (alg)
        return pkey
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
    spkac = SPKAC (spkac_encoded)
    assert spkac.challenge == 'WtQWMrqzBqTvIZTm-g44Hsr1-qczPFiQlw5Wsw'
