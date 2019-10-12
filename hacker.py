#!/usr/bin/python3
import urllib.parse
import hmac
import base64
import argparse
import logging
from os import path
import sys
from tqdm import tqdm

sys.path.append(path.join(path.dirname(path.realpath(__file__)), "opencl_brute"))

from Library import opencl
from Library.opencl_information import opencl_information

logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description='Decrypt the encrypted data from an Entrust IdentityGuard QR code')
parser.add_argument('platform', type=int, help='Run without this arguments to see a list of available opencl platform numbers')
parser.add_argument('URI', type=str, help='Example: igmobileotp://?action=secactivate&enc=VRUq6IoLWQRCMRITZEHtHUSWJiPwgu%2FN1BFyUHE5kxuHIEYoE3zmNTrAHeeUM5S3gzCnTy%2F%2Bdnbu%2FsjjQW%2BNEISx8C4ra8rLpxOl8E8w4KXHgjeBRgdvSzl%2BbzX5RYRrQlWgK8hsBT4pQYE0eFgW2TmRbzXu1Mu7XjKDcwsJLew32jQC2qyPLP8hljnv2rHwwsMfhQwgJUJYfctwLWWEDUFukEckaZ4O&v=1&mac=mhVL8BWKaishMa5%2B'.replace("%", "%%"))

try:
    args = parser.parse_args()
except SystemExit as e:
    print("\n-----------------------------------------------------------------")
    info = opencl_information()
    info.printplatforms()
    print("-----------------------------------------------------------------")
    raise e

# Parse URL
o = urllib.parse.urlparse(args.URI)

# Validate scheme
if o.scheme != 'igmobileotp':
    logging.warning("Only the scheme igmobileotp is currently supported")

logging.info("Scheme: %s", o.scheme)

# Parse query string
query = urllib.parse.parse_qs(o.query)

# Validate action
try:
    if query['action'][0] != 'secactivate':
        logging.warning("Only the secactivate action is currently supported")
    logging.info("Action: %s", query['action'][0])
except Exception:
    logging.warning("No action was found in the URI. Are you sure this is from a valid QR code?")

# Validate some encrypted data actually exists
enc = False
try:
    enc = query['enc'][0]
except Exception:
    raise Exception('An "enc" parameter is a required part of the URI')

# Decode the enc parameter from base64
try:
    enc = base64.b64decode(enc, validate=True)
except Exception:
    raise Exception('Could not decode base64 from enc paramater')

# Get the salt from enc
kdfSalt = enc[0:8]

logging.debug("KDF Salt: 0x%s", kdfSalt.hex())

opencl_algo = opencl.opencl_algos(args.platform, 0, False, inv_memory_density=1)

ctx = opencl_algo.cl_pbkdf2_init("sha256", len(kdfSalt), 64)


maced_payload = o.query[0:o.query.rfind('&')].encode('utf-8')  # mac is last param, so can remove it this way
correctmac = base64.b64decode(query['mac'][0])

hashes_per_batch = 100_000
assert 100_000_000 % hashes_per_batch == 0

with tqdm(total=100_000_000, unit='Hacks', unit_scale=True) as pbar:
    for batch_start in range(0, 100_000_000, hashes_per_batch):

        passwords = (str(n).encode('ascii') for n in range(batch_start, batch_start + hashes_per_batch))
        clResult = opencl_algo.cl_pbkdf2(ctx, passwords, kdfSalt, 1000, 64)

        for i, key in enumerate(clResult):
            hmacKey = key[16:48]
            digest = hmac.digest(hmacKey, maced_payload, 'sha256')
            if digest[0:12] == correctmac:
                print(f"Hax complete: {batch_start + i}")

        pbar.update(hashes_per_batch)
