"""boto3 through credproxy, configured as the README says. Run by tests/s3.rs (boto3_through_the_proxy).

usage: boto3_client.py <endpoint url> <region> <bucket> <token> <scratch dir>
Prints "ok" and exits 0 when every check passes.
"""

import hashlib
import os
import sys

import boto3
import botocore
from boto3.s3.transfer import TransferConfig
from botocore.config import Config

endpoint, region, bucket, token, scratch = sys.argv[1:6]


def credproxy_auth(request, **_):
    """The token instead of a signature, and the body's SHA-256 (credproxy signs it)."""
    body = request.body
    if body is None:
        data = b""
    elif isinstance(body, (bytes, bytearray)):
        data = bytes(body)
    elif isinstance(body, str):
        data = body.encode()
    else:
        pos = body.tell()
        data = body.read()
        body.seek(pos)
    request.headers["x-amz-content-sha256"] = hashlib.sha256(data).hexdigest()
    request.headers["Authorization"] = f"Bearer {token}"


s3 = boto3.client(
    "s3",
    endpoint_url=endpoint,
    region_name=region,
    config=Config(
        signature_version=botocore.UNSIGNED,
        request_checksum_calculation="when_required",
        response_checksum_validation="when_required",
        s3={"addressing_style": "path"},
        retries={"max_attempts": 1},
    ),
)
s3.meta.events.register("request-created.s3", credproxy_auth)


def sha(b):
    return hashlib.sha256(b).hexdigest()


# small object, odd key
key = "boto/dir with space/a+b=c&d.txt"
s3.put_object(Bucket=bucket, Key=key, Body=b"hello from boto3")
assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == b"hello from boto3"
assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == 16

# multipart upload_file / download_file with concurrency
big = os.urandom(23 * 1024 * 1024 + 17)
src = os.path.join(scratch, "big.bin")
dst = os.path.join(scratch, "big.out")
with open(src, "wb") as f:
    f.write(big)
cfg = TransferConfig(multipart_threshold=8 << 20, multipart_chunksize=8 << 20, max_concurrency=4)
s3.upload_file(src, bucket, "boto/big.bin", Config=cfg)
s3.download_file(bucket, "boto/big.bin", dst, Config=cfg)
with open(dst, "rb") as f:
    assert sha(f.read()) == sha(big), "multipart round trip differs"

# ranged get, listing, delete
r = s3.get_object(Bucket=bucket, Key="boto/big.bin", Range="bytes=100-199")
assert r["Body"].read() == big[100:200]
# (listed keys skip the "+" one: s3s-fs ignores encoding-type=url, so boto3's decoding turns "+" into " ")
s3.put_object(Bucket=bucket, Key="boto/list/x=1&y.txt", Body=b"1")
keys = [o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix="boto/list/")["Contents"]]
assert keys == ["boto/list/x=1&y.txt"], keys
s3.delete_object(Bucket=bucket, Key="boto/big.bin")
try:
    s3.head_object(Bucket=bucket, Key="boto/big.bin")
    raise AssertionError("still there after delete")
except botocore.exceptions.ClientError as e:
    assert e.response["Error"]["Code"] in ("404", "NoSuchKey"), e.response

# what credproxy refuses is refused, not changed
try:
    s3.copy_object(Bucket=bucket, Key="boto/copy", CopySource={"Bucket": bucket, "Key": key})
    raise AssertionError("copy went through")
except botocore.exceptions.ClientError as e:
    assert e.response["ResponseMetadata"]["HTTPStatusCode"] == 403, e.response
print("ok")
