import os


def local_maintenance():
    # Deliberately unsafe API usage, but no untrusted-input source reaches it.
    return os.system("printf fixture-only")
