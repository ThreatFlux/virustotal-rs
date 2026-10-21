#!/usr/bin/env python3
"""Exercise the real MCP file-report HTTPS client through an isolated mock proxy."""

import argparse
import json
from pathlib import Path
import socketserver
import ssl
import subprocess
import tempfile
import threading

from smoke_mcp_container import docker_command, request, wait_ready


FILE_HASH = "a" * 64
TOOL_REQUEST = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": "get_file_report", "arguments": {"hash": FILE_HASH}}}


def read_headers(connection):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = connection.recv(4096)
        if not chunk or len(data) + len(chunk) > 65536:
            raise ValueError("invalid fixture request headers")
        data += chunk
    return data


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            headers = read_headers(self.request)
            if headers.split(b"\r\n", 1)[0] != b"CONNECT www.virustotal.com:443 HTTP/1.1":
                raise ValueError("fixture refuses any other CONNECT target")
            self.server.connections += 1
            self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            with self.server.context.wrap_socket(self.request, server_side=True) as secured:
                self.serve_report(secured)
        except (OSError, ValueError) as error:
            self.server.failures.append(str(error))

    def serve_report(self, connection):
        headers = read_headers(connection)
        expected = f"GET /api/v3/files/{FILE_HASH} HTTP/1.1".encode()
        if headers.split(b"\r\n", 1)[0] != expected:
            raise ValueError("unexpected VirusTotal API fixture request")
        if b"x-apikey: fixture-api-key\r\n" not in headers.lower():
            raise ValueError("fixture must receive only its fabricated API credential")
        self.server.requests.append(expected.decode())
        body = json.dumps({"data": {"type": "file", "id": FILE_HASH,
                                    "attributes": {"meaningful_name": "fixture.bin"}}}).encode()
        response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
        response += f"Content-Length: {len(body)}\r\n\r\n".encode() + body
        connection.sendall(response)


class ProxyServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def create_certificates(root):
    commands = [["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                 "-subj", "/CN=Temporary MCP fixture CA", "-addext", "basicConstraints=critical,CA:TRUE",
                 "-keyout", str(root / "ca.key"), "-out", str(root / "ca.crt")]]
    for name, hostname in [("valid", "www.virustotal.com"), ("wrong", "wrong.fixture")]:
        extension = root / f"{name}.cnf"
        extension.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                             f"subjectAltName=DNS:{hostname}\nextendedKeyUsage=serverAuth\n")
        commands += [
            ["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={hostname}",
             "-keyout", str(root / f"{name}.key"), "-out", str(root / f"{name}.csr")],
            ["openssl", "x509", "-req", "-days", "1", "-in", str(root / f"{name}.csr"),
             "-CA", str(root / "ca.crt"), "-CAkey", str(root / "ca.key"), "-CAcreateserial",
             "-extfile", str(extension), "-out", str(root / f"{name}.crt")],
        ]
    for command in commands:
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (root / "ca.crt").chmod(0o644)


def run_server_case(image, platform, root, proxy, mode):
    environment = {"VIRUSTOTAL_API_KEY": "fixture-api-key", "HTTP_ADDR": "0.0.0.0:8080",
                   "HTTPS_PROXY": f"http://host.docker.internal:{proxy.server_address[1]}",
                   "NO_PROXY": "localhost,127.0.0.1"}
    command = docker_command(image, platform, environment)
    command.remove("--rm")
    command += ["--add-host", "host.docker.internal:host-gateway"]
    if mode != "untrusted":
        command += ["-v", f"{root}/ca.crt:/fixture/ca.crt:ro", "-e", "SSL_CERT_FILE=/fixture/ca.crt"]
    container = subprocess.check_output(command + ["-d", "-p", "127.0.0.1::8080", "--", image], text=True).strip()
    try:
        address = subprocess.check_output(["docker", "port", container, "8080/tcp"], text=True).strip()
        url = "http://" + address
        wait_ready(url, container)
        status, body, _ = request(url + "/", TOOL_REQUEST, timeout=15)
        logs = subprocess.check_output(["docker", "logs", container], text=True, stderr=subprocess.STDOUT)
        validate_response(mode, status, json.loads(body), logs, proxy)
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)


def validate_response(mode, status, result, logs, proxy):
    if not proxy.connections:
        raise RuntimeError("real SDK request did not use the isolated proxy")
    if mode == "valid":
        content = result.get("result", {}).get("content", [])
        if status != 200 or not content or json.loads(content[0]["text"]).get("id") != FILE_HASH:
            raise RuntimeError(f"trusted MCP HTTPS report failed: {result}; {proxy.failures}")
        if len(proxy.requests) != 1:
            raise RuntimeError("fixture did not observe exactly one authenticated HTTPS API request")
        return
    if "error" not in result or proxy.requests:
        raise RuntimeError(f"MCP accepted an invalid certificate: {result}; {proxy.failures}")
    causes = ("unknownissuer", "unknown issuer") if mode == "untrusted" else ("notvalidforname", "not valid for name")
    if not any(cause in logs.lower() for cause in causes):
        raise RuntimeError(f"expected a certificate-specific {mode} failure: {logs}; {proxy.failures}")


def check_case(image, platform, root, mode):
    certificate = "wrong" if mode == "hostname" else "valid"
    proxy = ProxyServer(("0.0.0.0", 0), ProxyHandler)
    proxy.connections, proxy.requests, proxy.failures = 0, [], []
    proxy.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    proxy.context.minimum_version = ssl.TLSVersion.TLSv1_2
    proxy.context.load_cert_chain(root / f"{certificate}.crt", root / f"{certificate}.key")
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        run_server_case(image, platform, root, proxy, mode)
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="mcp-https-") as directory:
        root = Path(directory)
        create_certificates(root)
        for mode in ("valid", "untrusted", "hostname"):
            check_case(args.image, args.platform, root, mode)
    print(f"MCP HTTPS verified: {args.image}; actual file report, unknown issuer and hostname rejection")


if __name__ == "__main__":
    main()
