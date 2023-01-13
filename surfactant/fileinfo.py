import os
from hashlib import sha256, sha1, md5


def get_file_info(filename):
    try:
        fstats = os.stat(filename)
    except FileNotFoundError:
        return None
    else:
        return {"size": fstats.st_size, "accesstime": fstats.st_atime, "modifytime": fstats.st_mtime, "createtime": fstats.st_ctime}
    

def calc_file_hashes(filename):
    sha256_hash = sha256()
    sha1_hash = sha1()
    md5_hash = md5()
    b = bytearray(4096)
    mv = memoryview(b)
    try:
        with open(filename, "rb", buffering=0) as f:
            while n := f.readinto(mv):
                sha256_hash.update(mv[:n])
                sha1_hash.update(mv[:n])
                md5_hash.update(mv[:n])
    except FileNotFoundError:
        return None
    return {"sha256": sha256_hash.hexdigest(), "sha1": sha1_hash.hexdigest(), "md5": md5_hash.hexdigest()}