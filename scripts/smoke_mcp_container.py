#!/usr/bin/env python3
"""Verify the real MCP container's health, JWT/OAuth modes and stdio transport."""

import argparse
import base64
import contextlib
import hashlib
import http.server
import json
import re
import secrets
# Required for shell-free Docker/OpenSSL test commands.
import subprocess  # nosec B404
import sys
import time
import threading
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlencode, urlsplit


REQUEST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}


def remove_container(container, force=False):
    """Enforce bounded cleanup without replacing an active validation failure."""
    primary_error = sys.exc_info()[1]
    command = ["docker", "rm"] + (["-f"] if force else []) + [container]
    try:
        # Fixed Docker executable, shell-free arguments, and an ID returned by Docker.
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL, timeout=20)  # nosec B603 # nosemgrep
    except (OSError, subprocess.SubprocessError) as cleanup_error:
        if primary_error is None:
            raise
        print(f"Container cleanup also failed: {cleanup_error}", file=sys.stderr)


@contextlib.contextmanager
def managed_container(command):
    """Name the container before creation so partial Docker startup failures are cleaned up."""
    container = "mcp-check-" + secrets.token_hex(12)
    command = command.copy()
    operand = command.index("--")
    command[operand:operand] = ["--name", container]
    try:
        # Fixed Docker executable, shell-free arguments, and a generated container name.
        subprocess.check_output(command, text=True, timeout=60)  # nosec B603 # nosemgrep
        yield container
    finally:
        remove_container(container, force=True)


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


def request(url, body=None, token=None, timeout=3, cookie=None):
    """Send JSON only to the loopback test server without following redirects."""
    parsed = urlsplit(url)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.username is not None or parsed.password is not None or not parsed.port):
        raise ValueError("test requests must target the loopback HTTP fixture")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
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
    logs = subprocess.check_output(["docker", "logs", container], text=True, timeout=20)  # nosec B603, B607 # nosemgrep
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
    credentials = json.loads(body)
    if credentials.get("expires_in") != 90:
        raise RuntimeError("JWT issuance did not advertise its configured token lifetime")
    token = credentials["access_token"]
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


class OAuthProvider(http.server.BaseHTTPRequestHandler):
    """Exchange only the fabricated code using the observed PKCE challenge."""

    def do_POST(self):
        """Verify code, client, redirect URI, and PKCE before returning a fixture token."""
        self.connection.settimeout(5)
        length = int(self.headers.get("Content-Length", "0"))
        if self.path != "/oauth/token" or not 0 < length < 8192:
            self.send_error(400)
            return
        form = parse_qs(self.rfile.read(length).decode())
        verifier = form.get("code_verifier", [""])[0]
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        if (form.get("code") != ["fixture-code"] or form.get("grant_type") != ["authorization_code"]
                or form.get("client_id") != ["fixture-client"]
                or form.get("redirect_uri") != ["http://127.0.0.1:8080/fixture/callback"]
                or challenge != self.server.challenge):
            self.send_error(400)
            return
        self.server.exchanges += 1
        self.server.token = secrets.token_urlsafe(32)
        self.server.tokens.append(self.server.token)
        # Bearer is the OAuth token type; the fabricated access token is generated randomly.
        response = {"access_token": self.server.token, "token_type": "Bearer"}  # nosec B105
        if self.server.expires_in is not None:
            response["expires_in"] = self.server.expires_in
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        """Keep authorization codes and token requests out of fixture access logs."""


@contextlib.contextmanager
def oauth_provider():
    """Expose an isolated host fixture to Docker and always stop its server thread."""
    # The container reaches this ephemeral fixture via host-gateway; no upstream traffic or real credentials.
    provider = http.server.ThreadingHTTPServer(("0.0.0.0", 0), OAuthProvider)  # nosec B104
    provider.token, provider.challenge, provider.exchanges, provider.tokens = None, None, 0, []
    provider.issuer = f"http://host.docker.internal:{provider.server_port}"
    provider.expires_in = 3600
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    try:
        yield provider
    finally:
        provider.shutdown()
        provider.server_close()
        thread.join(timeout=10)


def check_oauth(url, provider):
    """Complete browser-bound OAuth, verify authenticated MCP, and reject CSRF and replay."""
    if request(url + "/", REQUEST)[0] != 401:
        raise RuntimeError("OAuth MCP endpoint accepted an unauthenticated request")
    status, _, headers = request(url + "/oauth/authorize")
    location = urlsplit(headers.get("Location", ""))
    if status not in (302, 303, 307) or location.netloc != urlsplit(provider.issuer).netloc:
        raise RuntimeError("OAuth did not redirect to the isolated identity fixture")
    query = parse_qs(location.query)
    if query.get("code_challenge_method") != ["S256"]:
        raise RuntimeError("OAuth did not request PKCE SHA-256")
    provider.challenge = query["code_challenge"][0]
    cookie = headers.get("Set-Cookie", "").split(";", 1)[0]
    callback = url + "/fixture/callback?" + urlencode({"code": "fixture-code", "state": query["state"][0]})
    if request(callback)[0] != 400:
        raise RuntimeError("OAuth callback accepted a missing browser binding")
    if request(url + "/fixture/callback?code=fixture-code&state=wrong", cookie=cookie)[0] != 400:
        raise RuntimeError("OAuth callback accepted an incorrect state")
    return check_oauth_exchange(url, provider, callback, cookie)


def check_oauth_exchange(url, provider, callback, cookie):
    """Verify callback response, bearer authorization, replay rejection, and invalid tokens."""
    exchanges = provider.exchanges
    status, body, headers = request(callback, cookie=cookie)
    if status != 200 or headers.get("Cache-Control") != "no-store" or provider.exchanges != exchanges + 1:
        raise RuntimeError("OAuth token exchange did not complete exactly once without caching")
    credentials = json.loads(body)
    if credentials.get("expires_in") != 3600:
        raise RuntimeError("OAuth callback did not advertise the bounded accepted token lifetime")
    token = credentials["access_token"]
    status, body, _ = request(url + "/", REQUEST, token)
    if token != provider.token or status != 200 or not json.loads(body).get("result", {}).get("tools"):
        raise RuntimeError("OAuth bearer token did not authorize the real MCP tools list")
    if request(callback, cookie=cookie)[0] != 400 or provider.exchanges != exchanges + 1:
        raise RuntimeError("OAuth callback permitted replay")
    if request(url + "/", REQUEST, "invalid-token")[0] != 401:
        raise RuntimeError("OAuth accepted an invalid bearer token")
    return token


def check_oauth_clients(url, provider):
    """Ensure independent browser logins retain independent, simultaneously valid bearer tokens."""
    first = check_oauth(url, provider)
    provider.expires_in = None
    second = check_oauth(url, provider)
    if first == second:
        raise RuntimeError("identity fixture did not issue independent client tokens")
    if request(url + "/", REQUEST, first)[0] != 200:
        raise RuntimeError("a second OAuth client login revoked the first client's token")
    check_authorization_budget(url, first)


def check_authorization_budget(url, token):
    """Throttle anonymous starts while preserving an existing client's authenticated RPC traffic."""
    for _ in range(100):
        status, _, headers = request(url + "/oauth/authorize")
        if status == 429:
            if headers.get("Retry-After") != "2":
                raise RuntimeError("authorization throttling omitted retry guidance")
            if request(url + "/", REQUEST, token)[0] != 200:
                raise RuntimeError("authorization throttling blocked an authenticated MCP client")
            return
        if status not in (302, 303, 307):
            raise RuntimeError(f"unexpected authorization status during flood: {status}")
    raise RuntimeError("anonymous authorization requests bypassed the peer budget")


def check_server(image, platform, mode, provider=None):
    """Exercise HTTP authentication and ensure credentials never appear in logs."""
    password = secrets.token_urlsafe(32)
    environment = {"VIRUSTOTAL_API_KEY": "fixture-api-key", "HTTP_ADDR": "0.0.0.0:8080"}
    if mode == "jwt":
        environment.update(ENABLE_JWT="1", JWT_SECRET=secrets.token_urlsafe(48),
                           MCP_AUTH_USERNAME="fixture-user", MCP_AUTH_PASSWORD=password, JWT_EXPIRY_SECONDS="90")
    else:
        environment.update(ENABLE_OAUTH="1", OAUTH_CLIENT_ID="fixture-client",
                           OAUTH_AUTH_SERVER_URL=provider.issuer,
                           OAUTH_REDIRECT_URI="http://127.0.0.1:8080/fixture/callback")
    command = docker_command(image, platform, environment)
    command.remove("--rm")
    if provider is not None:
        command += ["--add-host", "host.docker.internal:host-gateway"]
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    with managed_container(command + ["-d", "-p", "127.0.0.1::8080", "--", image]) as container:
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        address = subprocess.check_output(["docker", "port", container, "8080/tcp"], text=True, timeout=20).strip()  # nosec B603, B607 # nosemgrep
        url = "http://" + address
        wait_ready(url, container)
        if mode == "jwt":
            check_jwt(url, password)
        else:
            check_oauth_clients(url, provider)
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        logs = subprocess.check_output(["docker", "logs", container], text=True, stderr=subprocess.STDOUT, timeout=20)  # nosec B603, B607 # nosemgrep
        if re.search(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", logs):
            raise RuntimeError("MCP startup/request logs exposed a signed JWT")
        if provider is not None and any(token in logs for token in provider.tokens):
            raise RuntimeError("MCP logs exposed the OAuth access token")
        if "admin/admin123" in logs or "user/user123" in logs:
            raise RuntimeError("MCP startup logs still advertise demo credentials")
        # Fixed executable and argument list; no shell interprets image names or fixture data.
        subprocess.run(["docker", "stop", "--time", "5", container], check=True, stdout=subprocess.DEVNULL, timeout=20)  # nosec B603, B607 # nosemgrep


def check_missing_secret(image, platform):
    """Require JWT startup to fail closed without a signing secret."""
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "ENABLE_JWT": "1"})
    # Fixed executable and argument list; no shell interprets image names or fixture data.
    result = subprocess.run(command + ["--", image], capture_output=True, text=True, timeout=20)  # nosec B603, B607 # nosemgrep
    if not result.returncode or "JWT_SECRET is required" not in result.stderr:
        raise RuntimeError(f"JWT startup did not fail closed without signing configuration: {result.stderr}")


def check_invalid_mode(image, platform):
    """Reject misspelled transport names instead of unexpectedly starting an HTTP listener."""
    command = docker_command(image, platform, {"VIRUSTOTAL_API_KEY": "fixture-api-key", "SERVER_MODE": "sdtio"})
    # Fixed Docker executable and shell-free arguments; the image is a validated operand.
    result = subprocess.run(command + ["--", image], capture_output=True, text=True, timeout=20)  # nosec B603 # nosemgrep
    if not result.returncode or "Unsupported SERVER_MODE" not in result.stderr:
        raise RuntimeError("invalid transport mode did not fail closed")


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
    check_invalid_mode(args.image, args.platform)
    check_missing_secret(args.image, args.platform)
    check_server(args.image, args.platform, "jwt")
    with oauth_provider() as provider:
        check_server(args.image, args.platform, "oauth", provider)
    check_stdio(args.image, args.platform)
    print(f"MCP container verified: {args.image}; health, JWT configured/invalid/missing, OAuth PKCE/callback/bearer/replay/multiple clients/rate limiting, stdio")


if __name__ == "__main__":
    main()
