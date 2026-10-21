#!/usr/bin/env python3
"""Verify the real MCP container's health, JWT/OAuth modes and stdio transport."""

import argparse
import json
import re
import secrets
# Required for shell-free Docker/OpenSSL test commands.
import subprocess  # nosec B404
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit


REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def image_reference(value):
    """Accept an image reference as one Docker operand and reject option-like input."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:-]*", value):
        raise argparse.ArgumentTypeError("expected a Docker image reference, not options or shell syntax")
    return value


def docker_command(image, platform, environment):
    """Build a shell-free Docker argument list with restricted runtime privileges."""
    image_reference(image)
    command = ["docker", "run", "--rm", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges"]
    if platform:
        command += ["--platform", platform]
    for name, value in environment.items():
        command += ["-e", f"{name}={value}"]
    return command


def request(url, body=None, token=None, timeout=3):
    """Send JSON only to the loopback test server without following redirects."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None or not parsed.port):
        raise ValueError("test requests must target the loopback HTTP fixture")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if body is None else json.dumps(body).encode()
    try:
        # Validated loopback HTTP only; redirects disabled.
        with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, data=data, headers=headers), timeout=timeout) as response:  # nosec B310
            return response.status, response.read(), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read(), error.headers


def wait_ready(url, container):
    """Poll container health and include server logs if startup times out."""
    for _ in range(60):
        try:
            if request(url + "/health")[0] == 200:
                return
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.25)
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    logs = subprocess.check_output(["docker", "logs", container], text=True)  # nosec B603, B607 # nosemgrep
    raise RuntimeError(f"MCP server did not become healthy: {logs}")


def check_jwt(url, password):
    """Verify configured credentials work while demo credentials and invalid tokens fail."""
    if request(url + "/", REQUEST)[0] != 401:
        raise RuntimeError("JWT MCP endpoint accepted an unauthenticated request")
    # Deliberately rejected test credentials, never valid secrets.
    for credentials in ({"username": "admin", "password": "admin123"},  # nosec B105
                        # Deliberately rejected test credentials, never valid secrets.
                        {"username": "fixture-user", "password": "incorrect"}):  # nosec B105
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
    """Expose redirects to assertions without contacting external providers."""
    def redirect_request(self, *_):
        """Keep redirects observable so tests never contact the identity provider."""
        return None


def check_oauth(url):
    """Require an OAuth redirect to the configured fixture identity provider."""
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
    """Exercise HTTP authentication and ensure credentials never appear in logs."""
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
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    container = subprocess.check_output(command + ["-d", "-p", "127.0.0.1::8080", "--", image], text=True).strip()  # nosec B603, B607 # nosemgrep
    try:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        address = subprocess.check_output(["docker", "port", container, "8080/tcp"], text=True).strip()  # nosec B603, B607 # nosemgrep
        url = "http://" + address
        wait_ready(url, container)
        if mode == "jwt":
            check_jwt(url, password)
        else:
            check_oauth(url)
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        logs = subprocess.check_output(["docker", "logs", container], text=True, stderr=subprocess.STDOUT)  # nosec B603, B607 # nosemgrep
        if re.search(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", logs):
            raise RuntimeError("MCP startup/request logs exposed a signed JWT")
        if "admin/admin123" in logs or "user/user123" in logs:
            raise RuntimeError("MCP startup logs still advertise demo credentials")
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        subprocess.run(["docker", "stop", "--time", "5", container], check=True, stdout=subprocess.DEVNULL, timeout=20)  # nosec B603, B607 # nosemgrep
    finally:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)  # nosec B603, B607 # nosemgrep


def check_missing_secret(image, platform):
    """Require JWT startup to fail closed without a signing secret."""
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "ENABLE_JWT": "1"})
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    result = subprocess.run(command + ["--", image], capture_output=True, text=True, timeout=20)  # nosec B603, B607 # nosemgrep
    if not result.returncode or "JWT_SECRET is required" not in result.stderr:
        raise RuntimeError(f"JWT startup did not fail closed without signing configuration: {result.stderr}")


def check_stdio(image, platform):
    """Validate startup and correlated tools-list JSON-RPC records on stdout."""
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "SERVER_MODE": "stdio"})
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    result = subprocess.run(command + ["-i", "--", image], input=json.dumps(REQUEST) + "\n",  # nosec B603, B607 # nosemgrep
                            capture_output=True, text=True, timeout=20)
    try:
        responses = [json.loads(line) for line in result.stdout.splitlines() if line]
    except json.JSONDecodeError as error:
        raise RuntimeError("stdio stdout contains diagnostic text outside JSON-RPC framing") from error
    if result.returncode or len(responses) != 2:
        raise RuntimeError("stdio must emit only its existing capabilities record and requested response")
    startup, response = responses
    if (startup.get("jsonrpc") != "2.0"
            or startup.get("result", {}).get("serverInfo", {}).get("name") != "virustotal-sdk"
            or not startup.get("result", {}).get("capabilities", {}).get("tools")):
        raise RuntimeError("stdio capabilities record is invalid")
    if (response.get("jsonrpc") != "2.0" or response.get("id") != REQUEST["id"]
            or not response.get("result", {}).get("tools")):
        raise RuntimeError("stdio did not return a valid correlated tools-list response")


def main():
    """Parse the image and platform arguments and run all verification checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=image_reference)
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    args = parser.parse_args()
    check_missing_secret(args.image, args.platform)
    check_server(args.image, args.platform, "jwt")
    check_server(args.image, args.platform, "oauth")
    check_stdio(args.image, args.platform)
    print(f"MCP container verified: {args.image}; health, JWT configured/invalid/missing, OAuth redirect, stdio")


if __name__ == "__main__":
    main()
