try :
    from pyspkac.spkac   import SPKAC
    from pyspkac.version import VERSION as version
except ImportError :
    ### when imported from setup.py, this should fail silently
    pass
