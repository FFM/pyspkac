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
