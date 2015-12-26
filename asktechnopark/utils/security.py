import hashlib
import base64


"""
Get Hash in base64 encoding
"""
def get_hash(str):
    m = hashlib.sha256()
    m.update(str)
    sha = m.digest()
    res = base64.b64encode(sha)
    return res