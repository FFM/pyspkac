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

import os
from distutils.core import setup

license     = 'GNU Library or Lesser General Public License (LGPL)'

description = open ('README.rst').read ()

# (re)-create version information in version.py
# Note: We find the first version on the parent tree to not match
# versions on a different tree resulting from a merge.
# Discussion see
# http://www.xerxesb.com/2010/git-describe-and-the-tale-of-the-wrong-commits/
try :
    os.stat ('.git')
except OSError :
    pass
else :
    import re
    from subprocess import Popen, PIPE
    tre  = re.compile (r'.*tag: (V[^ ),]*).*')
    cmd  = 'git log --oneline --decorate=short --first-parent'
    deco = Popen (cmd.split (), stdout=PIPE).communicate () [0].strip ()
    v    = None
    for line in deco.split ('\n') :
        if not v :
            v = line.split () [0]
        m = tre.search (line)
        if m :
            tag = m.group (1)
            cmd = 'git describe --tags --dirty=-modified --match=%s' % tag
            break
    else :
        cmd = 'git status --porcelain'
    version = Popen (cmd.split (), stdout = PIPE).communicate () [0].strip ()
    # No tags yet:
    if cmd.endswith ('porcelain') :
        for l in version.split ('\n') :
            if l.startswith ('??') :
                continue
            if l [0:2] != '  ' :
                v += '-modified'
                break
        version = v
    cmd     = 'git log -n 1'
    log     = Popen (cmd.split (), stdout = PIPE).communicate () [0].strip ()
    for line in log.split ('\n') :
        if line.startswith ('Date:') :
            date = line.split (':', 1) [1].strip ()
            break
    f = open ('pyspkac/version.py', 'w')
    print >> f, 'VERSION = "%s"' % version
    print >> f, 'DATE = "%s"'    % date
    f.close ()

from pyspkac.version import VERSION

setup \
    ( name             = "pyspkac"
    , version          = VERSION
    , url              = 'https://github.com/FFM/pyspkac'
    , description      = 
        "Support for netscape / html5 SPKAC client certificate request"
    , long_description = ''.join (description)
    , license          = license
    , author           = "Ralf Schlatterbeck"
    , author_email     = "rsc@runtux.com"
    , packages         = ['pyspkac']
    , platforms        = 'Any'
    , install_requires = ['M2Crypto', 'pyasn1']
    , classifiers      = \
        [ 'Development Status :: 4 - Beta'
        , 'License :: OSI Approved :: ' + license
        , 'Operating System :: OS Independent'
        , 'Programming Language :: Python'
        , 'Intended Audience :: Developers'
        , 'Topic :: Security :: Cryptography'
        , 'Topic :: Internet :: WWW/HTTP :: HTTP Servers'
        , 'Topic :: Software Development :: Libraries :: Python Modules'
        , 'Topic :: Internet :: WWW/HTTP :: Site Management'
        ]
    )
