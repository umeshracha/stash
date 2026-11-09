#!/usr/bin/env python3
"""Measure authenticated object transfers against a local Stash deployment."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import json
import math
import os
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

import boto3
from botocore.config import Config


def workload(client, name, size, count, workers):
    bodies = [os.urandom(size) for _ in range(workers)]
    keys = [f"{name}/{i:06}" for i in range(count)]
    bucket = "benchmark"

    def measure(operation):
        def transfer(index):
            key, body = keys[index], bodies[index % workers]
            start = time.perf_counter()
            if operation == "PUT":
                client.put_object(Bucket=bucket, Key=key, Body=body)
            else:
                response = client.get_object(Bucket=bucket, Key=key)
                with response["Body"] as stream:
                    if stream.read() != body:
                        raise ValueError(f"download mismatch for {key}")
            return (time.perf_counter() - start) * 1000

        start = time.perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as executor:
            latency = sorted(executor.map(transfer, range(count)))
        elapsed = time.perf_counter() - start
        return {
            "workload": name,
            "method": operation,
            "bytes_per_object": size,
            "requests": count,
            "concurrency": workers,
            "seconds": round(elapsed, 3),
            "requests_per_second": round(count / elapsed, 1),
            "mib_per_second": round(count * size / elapsed / 2**20, 2),
            "latency_ms": {
                f"p{percentile}": round(latency[math.ceil(count * percentile / 100) - 1], 2)
                for percentile in (50, 95, 99)
            },
        }

    return [measure(operation) for operation in ("PUT", "GET")]


@contextmanager
def running(command, log_path):
    with log_path.open("w+") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log)
        try:
            yield process
        except Exception:
            log.seek(0)
            print(log.read(), file=sys.stderr)
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def wait_ready(process, url, check=None, **request_options):
    request = Request(url, **request_options)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Process exited with status {process.returncode} before {url} was ready")
        try:
            with urlopen(request, timeout=0.5) as response:
                if check is None or check(response):
                    return
        except (URLError, TimeoutError):
            pass
        time.sleep(0.05)
    raise TimeoutError(f"{url} did not become ready")


def start_stash(stack, binary, directory, name, config):
    path = directory / f"{name}.json"
    path.write_text(json.dumps(config))
    return stack.enter_context(running([str(binary), "-config", str(path)], directory / f"{name}.log"))


def start_cluster(stack, binary, etcd, directory, port):
    urls = [f"http://127.0.0.1:{port + offset}" for offset in range(1, 11)]
    shard_urls, client_urls, peer_urls = urls[:4], urls[4:7], urls[7:]
    members = ",".join(f"member{i}={url}" for i, url in enumerate(peer_urls))
    etcd_processes = []
    for i, (client_url, peer_url) in enumerate(zip(client_urls, peer_urls)):
        name = f"member{i}"
        command = [
            str(etcd), "--name", name, "--data-dir", str(directory / name),
            "--listen-client-urls", client_url, "--advertise-client-urls", client_url,
            "--listen-peer-urls", peer_url, "--initial-advertise-peer-urls", peer_url,
            "--initial-cluster", members, "--initial-cluster-token", "stash-benchmark",
        ]
        etcd_processes.append(stack.enter_context(running(command, directory / f"{name}.log")))
    for process, url in zip(etcd_processes, client_urls):
        wait_ready(process, url + "/health", lambda response: json.load(response)["health"] == "true")

    token = "local-benchmark-shard-token"
    for i, url in enumerate(shard_urls):
        name = f"shard{i}"
        process = start_stash(stack, binary, directory, name, {
            "listen": url.removeprefix("http://"),
            "data_dir": str(directory / name),
            "shard_node_token": token,
        })
        namespace = "0" * 32
        wait_ready(process, f"{url}/.stash/shards/{namespace}",
                   method="HEAD", headers={"Authorization": "Bearer " + token})
    return {
        "cluster": {"name": "stash-benchmark", "endpoints": client_urls},
        "erasure": {"nodes": [{"endpoint": url, "token": token} for url in shard_urls], "parity": 2},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--layout", choices=("standalone", "erasure", "cluster"), required=True)
    parser.add_argument("--etcd", type=Path, help="etcd binary for the cluster benchmark")
    parser.add_argument("--port", type=int, default=19745)
    parser.add_argument("--work-dir", type=Path, help="parent directory for benchmark data")
    args = parser.parse_args()
    if args.layout == "cluster" and args.etcd is None:
        parser.error("--layout cluster requires --etcd")
    binary = args.binary.resolve(strict=True)
    address = f"127.0.0.1:{args.port}"
    endpoint = f"http://{address}"
    secret = "local-benchmark-secret"
    with tempfile.TemporaryDirectory(dir=args.work_dir) as temporary, ExitStack() as stack:
        directory = Path(temporary).resolve()
        config = {
            "listen": address,
            "data_dir": str(directory / "data"),
            "credentials": {"benchmark": {"secret": secret, "buckets": {"*": "admin"}}},
        }
        if args.layout == "erasure":
            drives = [directory / f"drive-{i}" for i in range(4)]
            for drive in drives:
                drive.mkdir()
            config["erasure"] = {"drives": list(map(str, drives)), "parity": 2}
        if args.layout == "cluster":
            config.update(start_cluster(stack, binary, args.etcd.resolve(strict=True), directory, args.port))
        server = start_stash(stack, binary, directory, "stash", config)
        wait_ready(server, endpoint + "/readyz")
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name="us-east-1",
            aws_access_key_id="benchmark",
            aws_secret_access_key=secret,
            config=Config(s3={"addressing_style": "path"}, retries={"total_max_attempts": 1}),
        )
        try:
            client.create_bucket(Bucket="benchmark")
            workload(client, "warmup", 256 * 1024, 8, 4)
            results = workload(client, "small", 4096, 256, 8)
            results += workload(client, "large", 2 * 1024 * 1024, 64, 4)
        finally:
            client.close()
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    rss_mib = usage.ru_maxrss / (2**20 if sys.platform == "darwin" else 1024)
    print(json.dumps({
        "layout": args.layout,
        "results": results,
        "server_processes": 8 if args.layout == "cluster" else 1,
        "server_user_cpu_seconds": round(usage.ru_utime, 3),
        "server_system_cpu_seconds": round(usage.ru_stime, 3),
        "server_peak_rss_mib": round(rss_mib, 2),
    }, indent=2))


if __name__ == "__main__":
    main()
