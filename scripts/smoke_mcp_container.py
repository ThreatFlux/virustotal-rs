#!/usr/bin/env python3
"""Verify the real MCP container's health, JWT/OAuth modes and stdio transport."""

import argparse
import json
import secrets
import subprocess
import time
import urllib.error
import urllib.request


REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def docker_command(image, platform, environment):
    command = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges"]
    if platform:
        command += ["--platform", platform]
    for name, value in environment.items():
        command += ["-e", f"{name}={value}"]
    return command


def request(url, body=None, token=None, timeout=3):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data, headers=headers), timeout=timeout) as response:
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def wait_ready(url, container):
    for _ in range(60):
        try:
            if request(url + "/health")[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    logs = subprocess.check_output(["docker", "logs", container], text=True)
    raise RuntimeError(f"MCP server did not become healthy: {logs}")


def check_jwt(url, password):
    if request(url + "/", REQUEST)[0] != 401:
        raise RuntimeError("JWT MCP endpoint accepted an unauthenticated request")
    for credentials in ({"username": "admin", "password": "admin123"},
                        {"username": "fixture-user", "password": "incorrect"}):
        if request(url + "/auth/token", credentials)[0] != 401:
            raise RuntimeError("JWT issuer accepted demo or incorrect credentials")
    status, body, _ = request(url + "/auth/token", {"username": "fixture-user", "password": password})
    if status != 200:
        raise RuntimeError(f"configured JWT credentials failed: {status}")
    token = json.loads(body)["access_token"]
    status, body, _ = request(url + "/", REQUEST, token)
    if status != 200 or not json.loads(body).get("result", {}).get("tools"):
        raise RuntimeError("valid JWT did not authorize the MCP tools list")
    if request(url + "/", REQUEST, "invalid-token")[0] != 401:
        raise RuntimeError("invalid JWT was accepted")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def check_oauth(url):
    if request(url + "/", REQUEST)[0] != 401:
        raise RuntimeError("OAuth MCP endpoint accepted an unauthenticated request")
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(url + "/oauth/authorize", timeout=3)
    except urllib.error.HTTPError as error:
        if error.code in (302, 303, 307) and error.headers.get("Location", "").startswith("https://identity.fixture/"):
            return
        raise RuntimeError(f"unexpected OAuth authorization response: {error.code}") from error
    raise RuntimeError("OAuth authorization did not redirect to the configured identity provider")


def check_server(image, platform, mode):
    password = secrets.token_urlsafe(32)
    environment = {"VIRUSTOTAL_API_KEY": "fixture-api-key", "HTTP_ADDR": "0.0.0.0:8080"}
    if mode == "jwt":
        environment.update(ENABLE_JWT="1", JWT_SECRET=secrets.token_urlsafe(48),
                           MCP_AUTH_USERNAME="fixture-user", MCP_AUTH_PASSWORD=password)
    else:
        environment.update(ENABLE_OAUTH="1", OAUTH_CLIENT_ID="fixture-client",
                           OAUTH_AUTH_SERVER_URL="https://identity.fixture")
    command = docker_command(image, platform, environment)
    command.remove("--rm")
    container = subprocess.check_output(command + ["-d", "-p", "127.0.0.1::8080", "--", image], text=True).strip()
    try:
        address = subprocess.check_output(["docker", "port", container, "8080/tcp"], text=True).strip()
        url = "http://" + address
        wait_ready(url, container)
        if mode == "jwt":
            check_jwt(url, password)
        else:
            check_oauth(url)
        subprocess.run(["docker", "stop", "--time", "5", container], check=True, stdout=subprocess.DEVNULL, timeout=20)
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)


def check_missing_secret(image, platform):
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "ENABLE_JWT": "1"})
    result = subprocess.run(command + ["--", image], capture_output=True, text=True, timeout=20)
    if not result.returncode or "JWT_SECRET is required" not in result.stderr:
        raise RuntimeError(f"JWT startup did not fail closed without signing configuration: {result.stderr}")


def check_stdio(image, platform):
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "SERVER_MODE": "stdio"})
    result = subprocess.run(command + ["-i", "--", image], input=json.dumps(REQUEST) + "\n",
                            capture_output=True, text=True, timeout=20)
    responses = []
    for line in result.stdout.splitlines():
        try:
            responses.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if result.returncode or not any(item.get("result", {}).get("tools") for item in responses):
        raise RuntimeError(f"stdio MCP tools request failed: {result.stdout}\n{result.stderr}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    check_missing_secret(args.image, args.platform)
    check_server(args.image, args.platform, "jwt")
    check_server(args.image, args.platform, "oauth")
    check_stdio(args.image, args.platform)
    print(f"MCP container verified: {args.image}; health, JWT configured/invalid/missing, OAuth redirect, stdio")


if __name__ == "__main__":
    main()
