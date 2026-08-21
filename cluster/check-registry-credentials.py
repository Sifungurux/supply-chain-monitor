#!/usr/bin/env python3
"""A two-registry values file must render a usable merged docker config.

WHY THIS EXISTS

Every registry credential in this chart ends up in one docker
config.json, and every consumer authenticates from it: oras via
--registry-config, trivy/grype/cosign via DOCKER_CONFIG, unpacker via
--config. Each of those failure modes is silent in the same way -- a
credential that does not arrive produces an anonymous pull, and an
anonymous pull against a public registry SUCCEEDS with fewer results
rather than failing. There is no error to notice.

Three specific ways the rendering can be wrong while `helm template`
still exits 0, all of which this checks:

  - the auths map is empty or missing a configured host, so that
    registry is never authenticated;
  - the Secret is mounted under its own key name (".dockerconfigjson")
    instead of being projected to "config.json", which is the only name
    go-containerregistry's keychain looks for -- the mount is present,
    readable, and ignored;
  - a CA is mounted but SSL_CERT_DIR does not name its directory, so
    the private issuer is not trusted and the pull fails a TLS
    handshake instead.

Renders the chart with an inline entry, an externally-managed
dockerconfigjson Secret, and both CA shapes, then asserts on the result.
"""

import base64
import json
import subprocess
import sys
import tempfile
import os

VALUES = """
monitorApi:
  registryCredentials:
    - host: ghcr.io
      username: bot
      password: ghp_secret
    - host: registry.internal:5000
      username: svc
      password: hunter2
      ca: |
        -----BEGIN CERTIFICATE-----
        MIIBexample
        -----END CERTIFICATE-----
    - existingDockerConfigSecret: external-pull-secret
      caSecret:
        name: external-ca
        key: ca.crt
"""

failures = []


def fail(msg):
    failures.append(msg)


def main():
    import yaml

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
        f.write(VALUES)
        values_path = f.name
    try:
        out = subprocess.run(
            ["helm", "template", "scm-ci", "charts/supply-chain-monitor", "-f", values_path],
            capture_output=True, text=True, check=True,
        ).stdout
    finally:
        os.unlink(values_path)

    docs = [d for d in yaml.safe_load_all(out) if d]

    # 1. The merged auths map covers both inline hosts.
    secret = next((d for d in docs
                   if d.get("kind") == "Secret"
                   and d["metadata"]["name"] == "scm-registry-credentials-inline"), None)
    if secret is None:
        fail("no scm-registry-credentials-inline Secret rendered for two inline registryCredentials entries")
    else:
        if secret.get("type") != "kubernetes.io/dockerconfigjson":
            fail(f"credential Secret type is {secret.get('type')!r}, want kubernetes.io/dockerconfigjson")
        try:
            auths = json.loads(base64.b64decode(secret["data"][".dockerconfigjson"]))["auths"]
        except Exception as exc:  # noqa: BLE001 -- any failure here is the bug
            fail(f"merged .dockerconfigjson is not valid JSON with an auths map: {exc}")
            auths = {}
        for host in ("ghcr.io", "registry.internal:5000"):
            if host not in auths:
                fail(f"host {host!r} missing from the merged auths map: {sorted(auths)}")
        for host, entry in auths.items():
            expected = base64.b64encode(
                f"{entry.get('username')}:{entry.get('password')}".encode()).decode()
            if entry.get("auth") != expected:
                fail(f"auth field for {host!r} is not base64(username:password)")

    # 2. Every credential Secret is projected to config.json, and both
    #    kinds -- chart-rendered and operator-supplied -- are mounted.
    dep = next((d for d in docs
                if d.get("kind") == "Deployment"
                and d["metadata"]["name"] == "monitor-api"), None)
    if dep is None:
        fail("no monitor-api Deployment rendered")
        return

    pod = dep["spec"]["template"]["spec"]
    volumes = {v["name"]: v for v in pod.get("volumes", [])}
    container = pod["containers"][0]
    mounts = {m["mountPath"]: m["name"] for m in container.get("volumeMounts", [])}
    env = {e["name"]: e.get("value") for e in container.get("env", [])}

    for secret_name in ("scm-registry-credentials-inline", "external-pull-secret"):
        vol_name = f"registry-auth-{secret_name}"
        path = f"/etc/scm/registry-auth/{secret_name}"
        if path not in mounts:
            fail(f"credential Secret {secret_name!r} is not mounted at {path}")
            continue
        items = volumes.get(vol_name, {}).get("secret", {}).get("items", [])
        if [i.get("path") for i in items] != ["config.json"]:
            fail(f"{secret_name!r} is not projected to config.json (items={items}) -- "
                 "go-containerregistry ignores any other name and pulls anonymously")

    if env.get("REGISTRY_AUTH_DIR") != "/etc/scm/registry-auth":
        fail(f"REGISTRY_AUTH_DIR is {env.get('REGISTRY_AUTH_DIR')!r}, want /etc/scm/registry-auth")

    forwarded = (env.get("SCAN_WORKER_REGISTRY_AUTH_SECRETS") or "").split(",")
    for secret_name in ("scm-registry-credentials-inline", "external-pull-secret"):
        if secret_name not in forwarded:
            fail(f"{secret_name!r} not forwarded to scan-worker Jobs "
                 f"(SCAN_WORKER_REGISTRY_AUTH_SECRETS={env.get('SCAN_WORKER_REGISTRY_AUTH_SECRETS')!r})")

    # 3. Every mounted CA directory is named by SSL_CERT_DIR.
    cert_dirs = (env.get("SSL_CERT_DIR") or "").split(":")
    ca_mounts = [p for p in mounts if p.startswith("/ca-extra-")]
    if not ca_mounts:
        fail("no extra CA mounted for entries carrying ca/caSecret")
    for path in ca_mounts:
        if path not in cert_dirs:
            fail(f"CA mounted at {path} but SSL_CERT_DIR={env.get('SSL_CERT_DIR')!r} does not name it")


if __name__ == "__main__":
    main()
    if failures:
        print("registry credential rendering check FAILED:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)
    print("registry credential rendering check passed")
