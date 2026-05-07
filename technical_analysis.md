[![BARGHEST Logo](https://barghest.asia/_astro/smalllogo.CGeTYl66_13G0i6.webp)](https://barghest.asia/)

[Contact Page](https://barghest.asia/contact/)

- [Home](https://barghest.asia/)
- [About](https://barghest.asia/about/)
- [Blog](https://barghest.asia/blog/)
- [Contacts](https://barghest.asia/contact/)

_A critical no-interaction proximal/adjacent remote code execution vulnerability in adbd's ADB-over-TCP authentication path._

![Security vulnerability research - Android ADB authentication bypass](https://barghest.asia/_astro/cve-2026-0073-adb-tls-auth-bypass.CRmNgIXE_ZajHLC.webp)

TAGS:

- [security](https://barghest.asia/tags/security)
- [vulnerability](https://barghest.asia/tags/vulnerability)
- [android](https://barghest.asia/tags/android)
- [adb](https://barghest.asia/tags/adb)
- [cve](https://barghest.asia/tags/cve)

~19 MIN

Image attribution: background bridge from [1971 Concrete Bridge](https://www.flickr.com/photos/hugo90/6980712643) by [JOHN LLOYD](https://www.flickr.com/photos/hugo90/), licensed under [CC BY 2.0](https://creativecommons.org/licenses/by/2.0/deed.en). Digital art by [SHOCKHAM](https://shockham.com/).

* * *

_A critical no-interaction proximal/adjacent remote code execution vulnerability in `adbd`’s ADB-over-TCP authentication path._

Version 1.0 · Last edited: May 5, 2026

## Summary

[CVE-2026-0073](https://source.android.com/docs/security/bulletin/2026/2026-05-01) is a critical no-interaction remote code execution vulnerability in Android `adbd`’s ADB-over-TCP authentication path. More precisely, it is not command injection or code injection in the narrow bug-class sense; it is an authentication bypass that lets a remote peer become an authorized ADB host and open a shell as the Android `shell` user. The vulnerable path is reached after the peer speaks enough of the ADB transport to negotiate `STLS`, upgrades the connection to TLS, and presents a client certificate that is verified against the device’s paired ADB host trust store. Wireless debugging is the primary modern user-facing entry point, but the trust store is shared across ADB host authorization: paired host keys are stored in `/data/misc/adb/adb_keys`, and `adbd_tls_verify_cert` uses that store to decide whether the TLS peer is an authorized ADB host.

The bug sits at the boundary between three layers that normally make the feature safe: ADB packet negotiation, TLS 1.3 mutual authentication, and Android’s legacy RSA ADB host-key format. Stored ADB keys are decoded as RSA public keys, while the TLS client certificate’s public key is attacker-controlled and can use a different algorithm. The verifier then asks a generic OpenSSL/BoringSSL `EVP_PKEY` comparison API to compare those two objects.

In `adbd_tls_verify_cert`, Android compares these keys with `EVP_PKEY_cmp` and treats the return value as a boolean:

```
if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get())) {
    VLOG(AUTH) << "Matched auth_key=" << public_key;
    verified = true;
}
```

That is not the API contract inherited from OpenSSL-style `EVP_PKEY_cmp` semantics. Historically, `EVP_PKEY_cmp(a, b)` returned:

- `1` when the keys match.
- `0` when keys of the same type do not match.
- `-1` when the key types differ.
- `-2` when the operation is unsupported or otherwise cannot be completed.

The vulnerable caller accepts every non-zero value as success. That is subtle because same-type key mismatch returns `0`, so a random RSA certificate is rejected as expected. The bypass appears when the attacker presents a syntactically valid non-RSA certificate, such as EC P-256 or Ed25519. The comparison becomes RSA known key versus non-RSA presented key; the API returns a non-zero value for “different key types”; and `adbd` promotes that cross-algorithm mismatch into a successful host-key match.

The exploit is therefore more than “connect to an open port”. It must implement the ADB cleartext prelude, negotiate the `STLS` transition correctly, supply a cross-algorithm TLS client certificate, and then resume ADB framing inside the tunnel to open `shell:\x00`. Once those protocol requirements are met, the result is no-interaction RCE through an ADB shell, in the `shell` UID and SELinux domain. This includes user-enabled Wireless debugging, malware-enabled Wireless debugging where malware has enabled the platform `adbd` TCP service, and devices exposing ADB on TCP port `5555`, provided the exposed service reaches Android’s `adbd_tls_verify_cert` STLS/TLS authentication path and the device has at least one paired key in the shared ADB trust store.

## Acknowledgements

These findings were found during the process of building [MESH](https://github.com/BARGHEST-ngo/MESH).

This CVE was [found by BARGHEST](https://source.android.com/docs/security/overview/acknowledgements#:~:text=Ovi,0073).

## Affected configuration

To exploit the vulnerability, the following conditions are required:

- Developer options are enabled.
- ADB-over-TCP is enabled through Wireless debugging or another exposure of the platform `adbd` TCP service.
- `/data/misc/adb/adb_keys` contains at least one previously paired RSA ADB host key.
- The attacker can reach the device’s ADB TCP port, including on device application and deployments where the affected service is exposed on TCP port `5555`.

## Wireless debugging protocol shape

Wireless debugging is not simply “ADB on port 5555”. The modern path is a mixed ADB/TLS protocol:

1. The host opens a TCP connection to the Wireless debugging service port.
2. The host sends a cleartext ADB `CNXN` packet.
3. The device responds with `STLS`, indicating that the transport must be upgraded.
4. The host replies with `STLS`.
5. The host begins a TLS 1.3 handshake and presents a client certificate.
6. `adbd` verifies the certificate public key against the paired host keys.
7. If verification succeeds, normal ADB packets continue inside the TLS tunnel.

The important point is that the certificate verification step is the only thing binding the TLS client to a previously paired ADB host. Pairing creates trust in a host public key. Later Wireless debugging sessions are expected to prove possession of the corresponding private key. This bug breaks that proof.

## Vulnerability

The relevant code is in `platform/packages/modules/adb/daemon/auth.cpp`:

[https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/master/daemon/auth.cpp](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/master/daemon/auth.cpp)

```
int adbd_tls_verify_cert(X509_STORE_CTX* ctx, std::string* auth_key) {
    if (!auth_required) {
        // Any key will do.
        VLOG(AUTH) << __func__ << ": auth not required";
        return 1;
    }
    bool authorized = false;
    X509* cert = X509_STORE_CTX_get0_cert(ctx);
    if (cert == nullptr) {
        VLOG(AUTH) << "got null x509 certificate";
        return 0;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert));
    if (evp_pkey == nullptr) {
        VLOG(AUTH) << "got null evp_pkey from x509 certificate";
        return 0;
    }
    IteratePublicKeys([&](std::string_view public_key) {
        std::vector<std::string> split = android::base::Split(std::string(public_key), " \t");
        uint8_t keybuf[ANDROID_PUBKEY_ENCODED_SIZE + 1];
        const std::string& pubkey = split[0];
        if (b64_pton(pubkey.c_str(), keybuf, sizeof(keybuf)) != ANDROID_PUBKEY_ENCODED_SIZE) {
            LOG(ERROR) << "Invalid base64 key " << pubkey;
            return true;
        }
        RSA* key = nullptr;
        if (!android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key)) {
            LOG(ERROR) << "Failed to parse key " << pubkey;
            return true;
        }
        bool verified = false;
        bssl::UniquePtr<EVP_PKEY> known_evp(EVP_PKEY_new());
        EVP_PKEY_set1_RSA(known_evp.get(), key);
        if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get())) {
            VLOG(AUTH) << "Matched auth_key=" << public_key;
            verified = true;
        } else {
            VLOG(AUTH) << "auth_key doesn't match [" << public_key << "]";
        }
        RSA_free(key);
        if (verified) {
            *auth_key = public_key;
            authorized = true;
            return false;
        }
        return true;
    });
    return authorized ? 1 : 0;
}
```

The stored key path is fixed to RSA:

```
RSA* key = nullptr;
android_pubkey_decode(keybuf, ANDROID_PUBKEY_ENCODED_SIZE, &key);
...
EVP_PKEY_set1_RSA(known_evp.get(), key);
```

The peer key path is attacker-controlled:

```
bssl::UniquePtr<EVP_PKEY> evp_pkey(X509_get_pubkey(cert));
```

There is no algorithm check before comparison. Therefore the verifier compares a stored RSA key against whatever key type appears in the TLS client certificate.

The result is a predicate-looking crypto API trap. The code reads like:

```
if (keys_equal(a, b)) {
    accept();
}
```

But the function being called is not a boolean predicate. Under the inherited OpenSSL convention, negative values carry meaning. In C and C++, negative integers are truthy.

Curiously, this exact API pattern has produced security fixes before. OpenIKED was assigned CVE-2020-16088 for an authentication bypass caused by incorrect public-key match logic in `iked` due to the incorrect use of `EVP_PKEY_cmp()`. The same OpenBSD errata batch also fixed `rpki-client` for incorrect use of `EVP_PKEY_cmp` leading to an authentication bypass.

For the vulnerable path:

```
known_evp: RSA public key decoded from /data/misc/adb/adb_keys
evp_pkey:  EC P-256 or Ed25519 public key from attacker certificate
result:    EVP_PKEY_cmp(known_evp, evp_pkey) == -1
caller:    if (-1) verified = true
```

BoringSSL commit `3975388935512ea017024973924cfaf06f5b7822` is directly relevant:

[https://boringssl.googlesource.com/boringssl/+/3975388935512ea017024973924cfaf06f5b7822](https://boringssl.googlesource.com/boringssl/+/3975388935512ea017024973924cfaf06f5b7822)

The commit narrows `EVP_PKEY_cmp` and `EVP_PKEY_cmp_parameters` so they return only `1` or `0`, mapping the old negative cases to zero. The commit message explicitly describes the old return values as `1`, `0`, `-1`, and `-2`, and notes that the documentation was wrong about the negative values being errors.

The patch diff is here:

[https://boringssl.googlesource.com/boringssl/+/3975388935512ea017024973924cfaf06f5b7822%5E%21/#F0](https://boringssl.googlesource.com/boringssl/+/3975388935512ea017024973924cfaf06f5b7822%5E%21/#F0)

Google’s patch confirms the systemic nature that callers that used `EVP_PKEY_cmp` as a boolean predicate could mishandle cross-type comparisons.

Google also confirm the strict platform side fix is also in place where the platform fixes the authorization decision directly so only the exact keys match return value authorizes the peer (we predict it looks something like this):

```
if (EVP_PKEY_cmp(known_evp.get(), evp_pkey.get()) == 1) {
    verified = true;
}
```

## Exploitation and protocol

Your browser does not support the video tag.

The vulnerability is a logic error at the authentication boundary, in itself it appears like a relatively simple bug, but exploiting it was very challenging. Turning it into command execution was complex because of protocol alignment. We could not reach the vulnerable verifier by opening a socket and immediately starting TLS. We first had to drive `adbd` through the ADB-over-TCP state machine until the transport reached the `STLS` upgrade point, then present a client certificate with a public-key type that forced the cross-algorithm comparison case.

The first requirement was to speak enough of the ADB transport directly. ADB packets begin with a 24-byte little-endian header:

```
command      uint32
arg0         uint32
arg1         uint32
data_length  uint32
data_check   uint32  sum(payload) & 0xffffffff
magic        uint32  command ^ 0xffffffff
```

The relevant command words for this exploit path are:

```
CNXN  0x4e584e43
STLS  0x534c5453
OPEN  0x4e45504f
OKAY  0x59414b4f
WRTE  0x45545257
CLSE  0x45534c43
```

The first phase is cleartext ADB. A client sends `CNXN` with protocol version `0x01000001`, max data `256 * 1024`, and a plausible host feature string:

```
host::features=shell_v2,cmd,stat_v2,ls_v2,...
```

This step is mandatory because starting TLS immediately leaves the endpoint in the wrong state. We only reach `adbd_tls_verify_cert` after the device accepts the cleartext ADB prelude and responds with `STLS`. A response such as `AUTH` indicated a different ADB authentication path, and any response other than `STLS` meant the vulnerable TLS verifier had not been reached.

After receiving `STLS`, the client replies with a `STLS` packet and echoes the device’s `arg0` as the STLS version. This provides the conditions necessary to upgrade the existing TCP connection to TLS.

The second requirement is certificate selection. A normal paired ADB host uses an RSA key from the traditional ADB key format. For the bypass, we needed the TLS client certificate to carry a non-RSA public key so that `adbd` compared unlike `EVP_PKEY` types:

```
EC P-256    exploit case: cross-type comparison against stored RSA key
Ed25519     exploit case: cross-type comparison against stored RSA key
```

The TLS phase was kept narrow to make the certificate-verification result unambiguous. The connection used TLS 1.3, matching the observed wireless-debugging transport. Server-certificate verification was not the property under test; the relevant check was server-side verification of the client certificate. The client certificate presented during the handshake used EC P-256 or Ed25519.

During the TLS 1.3 handshake, `adbd` extracts the client certificate public key and calls `adbd_tls_verify_cert`. The vulnerable comparison occurs before any post-TLS ADB service is opened:

```
known_evp = RSA key decoded from /data/misc/adb/adb_keys
evp_pkey  = EC P-256 or Ed25519 key from client certificate
EVP_PKEY_cmp(known_evp, evp_pkey) -> non-zero cross-type result
if (result) authorized = true
```

A completed TLS handshake proved the authentication bypass, but it did not by itself prove command execution. It is necessary, therefore, to switch back to ADB framing inside the encrypted stream. The expected next packet from the device is `CNXN` over TLS, although robust exploitation needs to tolerate transition artifacts such as a stale `STLS` packet before the post-TLS `CNXN`.

The shell is opened as a normal ADB logical stream:

```
OPEN(local_id=1, remote_id=0, payload="shell:\x00")
```

The device had to respond with `OKAY`; the `arg0` in that response became the device’s remote stream ID. From that point on, shell I/O was carried in `WRTE` packets and acknowledged with `OKAY`. This is normal ADB stream discipline, but it is essential to exploitability: the authentication bypass only becomes remote code execution once the attacker can maintain a valid ADB service stream after TLS.

This means the exploit has three distinct gates:

- Transport gate: TCP reachability to the ADB-over-TCP service.
- Protocol gate: successful ADB `CNXN` -\> `STLS` -\> TLS transition.
- Authentication gate: acceptance of a cross-algorithm TLS client certificate against the shared ADB trust store.

Only after all three gates did the final ADB service gate occur: `OPEN shell:\x00` had to return `OKAY` rather than `CLSE`. On the vulnerable test device, once the TLS authentication gate was bypassed, the standard shell stream opened and produced `uid=2000(shell)` execution. Exploitation requires valid ADB packet structure, a correctly timed TLS upgrade, a certificate algorithm that reached the cross-type comparison case, and valid ADB stream semantics after the handshake.

## Threat model

The attack requires a reachable platform `adbd` TCP service that negotiates the `STLS` TLS client-authentication path and has at least one paired RSA host key in `/data/misc/adb/adb_keys`. Under those conditions, the attacker needs network reachability to the ADB endpoint, but not the paired host’s private key and not any interaction with the device UI.

The most direct scenario is local-network exposure: a developer, power user, or forensic analyst enables wireless debugging, pairs a legitimate host, and later joins an untrusted network while the service remains enabled. In our experience, this state is common in ADB-heavy workflows, especially in corperate buildings or in our case, for device forensics. Any peer that can reach the wireless debugging port can attempt to authenticate as an ADB host while that state persists.

The same model applies to internet-exposed ADB services. The relevant condition is not the port number, but whether the reachable endpoint is Android’s platform `adbd` taking the `CNXN` -\> `STLS` -\> TLS path, typically associated with Android 11 and later. In our exposure research, many candidate endpoints were discoverable on TCP port `5555`, including more than 10,000 exposed devices in Korea. That number should be treated as exposed ADB attack surface, not proof that every endpoint was vulnerable.

Software can also help create the prerequisite state. Local ADB helper workflows, popularized by tools such as Shizuku, show how on-device software can rely on the platform wireless-debugging or ADB-over-TCP path once the user or another component has enabled it. This methodology has now appeared in spyware: Osservatorio Nessuno’s April 2026 report on Morpheus describes Android spyware abusing Accessibility workflows to enable Developer options, turn on wireless debugging, and locally pair with `adbd`: [https://osservatorionessuno.org/blog/2026/04/morpheus-a-new-spyware-linked-to-ips-intelligence/](https://osservatorionessuno.org/blog/2026/04/morpheus-a-new-spyware-linked-to-ips-intelligence/). We confirmed by reverse engineering that Morpheus did not use this vulnerability. The point is narrower in that real-world spyware has been observed automating the same device state that this bug requires.

That software-assisted case should be interpreted carefully. Malware with enough Accessibility control to enable and pair wireless ADB may already be able to obtain `shell` privileges through the intended pairing flow. CVE-2026-0073 matters once the required state exists for any reason: any actor with network access to the affected `adbd` endpoint can attempt the cross-algorithm certificate bypass.

## Impact

The exploit does not provide kernel code execution, root, or direct compromise of hardware-backed secrets by itself. The demonstrated primitive is remote code execution as the Android `shell` user in SELinux context `u:r:shell:s0`. That is still a serious compromise: the attacker has reached the operating system’s debugging interface, not an ordinary application sandbox, an important contextual stage for Android security.

The practical impact depends on Android version, OEM policy, installed apps, and device configuration. From the ADB `shell` context, an attacker may be able to:

- Inspect system properties, logs, package state, process state, and device configuration.
- Access personal information exposed through logs, shared storage, notifications, bugreport material, or shell-readable app/debug state.
- Install, uninstall, enable, disable, or interact with packages through ADB-exposed package-management flows.
- Use `run-as` against debuggable applications.
- Exercise `cmd`, `settings`, `appops`, `pm`, `am`, and other shell-accessible system services.
- Stage follow-on exploitation from a context substantially more privileged than a normal application sandbox.

ADB does not automatically grant all private app data, and the `shell` context remains constrained by Android’s permission and SELinux model. The impact is that a remote network peer becomes an authorized debugging host without the paired host private key, gaining a powerful staging context for data access, account abuse, device reconfiguration, and follow-on exploitation. In spyware scenarios, that context can complement UI automation by launching activities, changing shell-accessible settings and permissions, reading available logs or notifications, installing helper packages, and coordinating account-takeover workflows.

## Advisory

- Install Android security updates and verify that the device’s security patch level includes the fix for CVE-2026-0073.
- Disable ADB when it is not actively needed.
- Avoid enabling Wireless debugging on untrusted Wi-Fi networks.
- Do not expose ADB or Wireless debugging beyond the local trusted network.
- Revoke unknown paired debugging hosts from Developer options.
- Turn off Developer options entirely on devices where they are not needed.
- Treat unexpected prompts to install carrier, SIM, network, security, or “configuration” apps as high risk.
- Review messaging-app linked devices and Google account sessions if you suspect spyware or forced configuration changes.

## Timeline

- November 20, 2025: Bug initially discovered in a form that required user interaction; closed as infeasible.
- December 13, 2025: Bug resubmitted to Google VDP after an exploit was developed without user interaction.
- January 9, 2026: Triage completed by Google and rated as critical severity.
- March 31, 2026: Patch distributed to production.
- May 4, 2026: CVE made public.
- May 5, 2026: Coordinated disclosure from BARGHEST and Google.

[![BARGHEST Logo](https://barghest.asia/_astro/BARGHEST.DXxbGmct_166wkI.webp)](https://barghest.asia/)

[Mastodon](https://infosec.exchange/@barghest) [X](https://x.com/barghestasia) [Github](https://github.com/BARGHEST-ngo)

[Home](https://barghest.asia/) [About](https://barghest.asia/about/) [Blog](https://barghest.asia/blog/) [Tags](https://barghest.asia/tags/) [Contacts](https://barghest.asia/contact/) [Privacy Policy](https://barghest.asia/privacy/) [RSS](https://barghest.asia/rss.xml)

[info@barghest.asia](mailto:info@barghest.asia)

CC0 No Rights Reserved
