#!/usr/bin/env python3
"""Serve an S3 API that lives under a path prefix at the root of another port.

vk-registry answers S3 under `/s3/`. boto3, the AWS CLI, rclone and the Go SDK take an
endpoint with a path and send `/s3/<bucket>/<key>`; ceph's s3-tests (host and port only)
and warp (`--host`) cannot. This proxy takes `/<bucket>/<key>` on its port and forwards
`/s3/<bucket>/<key>` to the registry.

A SigV4 signature covers the path, so a rewritten request cannot carry the client's
signature. The registry also takes the credentials its other routes take on `/s3/`, so the
proxy swaps the SigV4 `Authorization` for one of those: the Basic user when the access key
id is its name, else a bearer holding the access key id (an API key or a hub token is both
id and secret). The registry decodes `aws-chunked` bodies under such a credential without
checking chunk signatures, so SDK uploads pass through unchanged.

One request per connection: the proxy adds `Connection: close`, so the server closes after
answering and the client opens a new connection for its next request. That keeps the proxy
a byte pump, with no HTTP body parsing to get wrong, at the cost of a connection per
request, which is a cost in a benchmark. Standard library only.
"""

import argparse
import asyncio
import base64
import re
import sys

MAX_HEAD = 64 * 1024
CREDENTIAL = re.compile(r"Credential=([^/,\s]+)/")


class Settings:
    def __init__(self, args):
        self.upstream_host, port = args.upstream.rsplit(":", 1)
        self.upstream_port = int(port)
        self.prefix = args.prefix.rstrip("/").encode()
        self.basic_user = args.basic_user
        self.basic = None
        if args.basic_user and args.password_file:
            with open(args.password_file) as f:
                password = f.read().strip()
            self.basic = b"Basic " + base64.b64encode(
                f"{args.basic_user}:{password}".encode()
            )
        self.verbose = args.verbose


def rewrite_authorization(value: bytes, settings: Settings):
    """The credential the registry takes in place of a SigV4 header; others pass."""
    text = value.decode("latin-1")
    if not text.startswith("AWS4-HMAC-SHA256"):
        return value
    m = CREDENTIAL.search(text)
    if not m:
        return value
    key_id = m.group(1)
    if settings.basic is not None and key_id == settings.basic_user:
        return settings.basic
    return b"Bearer " + key_id.encode("latin-1")


def rewrite_head(head: bytes, settings: Settings) -> bytes:
    lines = head.split(b"\r\n")
    method, target, version = lines[0].split(b" ", 2)
    if not target.startswith(b"/"):
        raise ValueError("origin-form request target expected")
    out = [b" ".join((method, settings.prefix + target, version))]
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        lname = name.strip().lower()
        if lname in (b"connection", b"proxy-connection", b"keep-alive"):
            continue
        if lname == b"authorization":
            out.append(b"Authorization: " + rewrite_authorization(value.strip(), settings))
            continue
        out.append(line)
    out.append(b"Connection: close")
    if settings.verbose:
        print(f"{method.decode()} {target.decode()}", file=sys.stderr, flush=True)
    return b"\r\n".join(out) + b"\r\n\r\n"


async def pump(reader, writer, eof_only: bool):
    """Copy until EOF; then half-close (a request's end) or close (a response's)."""
    try:
        while chunk := await reader.read(64 * 1024):
            writer.write(chunk)
            await writer.drain()
        if eof_only and writer.can_write_eof():
            writer.write_eof()
        elif not eof_only:
            writer.close()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    except Exception as e:  # noqa: BLE001 - a pump's failure is a connection's, not the proxy's
        print(f"proxy: {e}", file=sys.stderr, flush=True)
        writer.close()


async def handle(client_r, client_w, settings: Settings):
    up_w = None
    try:
        try:
            head = await client_r.readuntil(b"\r\n\r\n")
        except asyncio.LimitOverrunError:
            client_w.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\n"
                           b"Connection: close\r\nContent-Length: 0\r\n\r\n")
            await client_w.drain()
            return
        except asyncio.IncompleteReadError:
            return
        new_head = rewrite_head(head[:-4], settings)
        up_r, up_w = await asyncio.open_connection(settings.upstream_host, settings.upstream_port)
        up_w.write(new_head)
        await up_w.drain()
        await asyncio.gather(pump(client_r, up_w, eof_only=True),
                             pump(up_r, client_w, eof_only=False))
    except (ConnectionResetError, BrokenPipeError, ValueError) as e:
        print(f"proxy: {e}", file=sys.stderr, flush=True)
    finally:
        for w in (client_w, up_w):
            if w is not None:
                w.close()
                try:
                    await w.wait_closed()
                except Exception:  # noqa: BLE001
                    pass


async def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--listen", default="127.0.0.1:5301", help="host:port to serve")
    p.add_argument("--upstream", default="127.0.0.1:5300", help="host:port of the registry")
    p.add_argument("--prefix", default="/s3", help="the path the S3 API lives under")
    p.add_argument("--basic-user", help="the registry's Basic user, for that access key id")
    p.add_argument("--password-file", help="that user's password")
    p.add_argument("--verbose", action="store_true", help="log every request")
    args = p.parse_args()
    settings = Settings(args)
    host, port = args.listen.rsplit(":", 1)
    server = await asyncio.start_server(
        lambda r, w: handle(r, w, settings), host, int(port), limit=MAX_HEAD)
    print(f"proxy: {args.listen} -> {args.upstream}{args.prefix}", file=sys.stderr, flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
