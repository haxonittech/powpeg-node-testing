# PowPeg Node Security Audit Report

**Repository:** rsksmart/powpeg-node
**Date:** 2026-03-19
**Scope:** Full codebase audit — all main Java sources (~140 files)
**Focus:** Exploit-focused audit targeting unauthenticated and low-privilege attack surfaces

---

## Executive Summary

This audit examined the entire powpeg-node codebase with a focus on realistic, exploitable vulnerabilities accessible to unauthenticated or low-privilege actors. The codebase implements a Bitcoin-RSK federation node that manages peg-in/peg-out operations through an HSM-backed signing architecture.

**Key architectural observation:** The system's security relies heavily on the HSM as a trust anchor — the HSM validates block headers, checks proof-of-work, enforces chaining, and controls signing keys. The powpeg node acts as a conduit between the RSK blockchain and the HSM. However, the communication channel between the node and HSM lacks fundamental security properties, creating the most significant attack surface in the system.

After rigorous analysis and false-positive elimination, **no vulnerabilities meeting the strict exploitability bar (100% confidence, practically exploitable by unauthenticated/low-privilege external actors) were identified**. However, several findings approach this bar in specific deployment configurations and are documented below.

---

## Detailed Findings

### Finding 1: Unbounded Recursion in HSM Version Retry — Denial of Service via StackOverflowError

**Severity:** Medium
**Confidence:** High
**Vulnerability Class:** Denial of Service (CWE-674: Uncontrolled Recursion)

**Affected files/functions:**
- `src/main/java/co/rsk/federate/signing/ECDSAHSMSigner.java:153-168` (`invokeWithVersionRetry`)

**Exact root cause:**
The `invokeWithVersionRetry` method recursively calls itself whenever `HSMChangedVersionException` is caught, with no retry limit or depth counter:

```java
} catch(HSMChangedVersionException e) {
    client = null;
    return invokeWithVersionRetry(keyId, call);  // No limit!
}
```

The `HSMChangedVersionException` is triggered when the HSM response contains error code `-904` (VERSION_CHANGED), as handled in `PowHSMResponseHandler.java:63-64`.

**Exact prerequisites:**
- Attacker must be able to intercept or control responses on the TCP socket between the powpeg node and the HSM device (MITM position or compromised HSM)
- The HSM socket uses plain TCP with no TLS (`SocketBasedJsonRpcClientProvider.java:80` — `new Socket()`)

**Step-by-step abuse path:**
1. Attacker achieves MITM position on the HSM TCP connection (e.g., ARP spoofing on same network segment, or compromise of the HSM gateway host)
2. When the node sends any signing or public key request, attacker responds with `{"errorcode": -904}`
3. The `PowHSMResponseHandler` throws `HSMChangedVersionException`
4. `ECDSAHSMSigner.invokeWithVersionRetry` catches it, nulls the client, and recurses
5. The new client creation queries version again → attacker returns `-904` again
6. Recursion continues until `StackOverflowError` kills the signing thread
7. All signing operations are disabled — no peg-outs can be processed by this federation member

**Why this is reachable in practice:**
- The HSM communication uses unencrypted plain TCP sockets (`SocketBasedJsonRpcClientProvider.java:80-93`)
- The socket timeout is 2 seconds, but each recursion creates a new connection attempt
- In environments where the HSM is on a separate network host, MITM is feasible
- Even in localhost deployments, a local-privilege attacker can intercept loopback traffic

**Realistic impact:**
- Complete denial of the signing service for the affected federation member
- If enough federation members are targeted, peg-out operations are halted
- The node must be restarted to recover

**Why it is NOT a false positive:**
1. ✅ The recursive call at line 163 has no depth limit — verified by reading the code directly
2. ✅ The `HSMChangedVersionException` is thrown from the production response handler path (`PowHSMResponseHandler.java:63-64`), not test-only code
3. ✅ The TCP socket is unencrypted (`new Socket()` at line 80 of `SocketBasedJsonRpcClientProvider.java`) — no TLS
4. ✅ Each recursion creates a new HSM client via `ensureHsmClient()` → `clientProvider.getSigningClient()` → `getVersion()`, which sends another request that the attacker can also intercept
5. ✅ No compensating control prevents the recursion — the `maxConnectionAttempts` in `HSMClientProtocol.send()` only limits connection failures, not version-changed errors which are semantically valid responses
6. ✅ The `StackOverflowError` is not caught anywhere in the call chain

**Minimal proof-of-concept idea:**
Create a TCP server on the HSM port that always responds with `{"errorcode": -904}` to any request. Connect the powpeg node to this server. Observe the signing thread crash with `StackOverflowError`.

**Recommended fix:**
Add a maximum retry counter to `invokeWithVersionRetry`:
```java
private <T> T invokeWithVersionRetry(KeyId keyId, SignerCall<T> call, int retriesLeft) throws SignerException {
    // ... existing code ...
    } catch(HSMChangedVersionException e) {
        if (retriesLeft <= 0) {
            throw new SignerException("HSM version changed too many times", e);
        }
        client = null;
        return invokeWithVersionRetry(keyId, call, retriesLeft - 1);
    }
}
```

---

### Finding 2: No Timeout on HSM Future.get() — Permanent Signing Thread Deadlock

**Severity:** Medium
**Confidence:** High
**Vulnerability Class:** Denial of Service (CWE-835: Infinite Loop / CWE-400: Resource Exhaustion)

**Affected files/functions:**
- `src/main/java/co/rsk/federate/signing/hsm/client/HSMClientProtocol.java:98-102` (`send` method)

**Exact root cause:**
The `send` method uses a static single-threaded executor (`Executors.newSingleThreadExecutor()` at line 170) and calls `future.get()` at line 102 with **no timeout**:

```java
Future<JsonNode> future = getExecutor().submit(new HSMRequest(client, command));
// ...
result = future.get();  // No timeout!
```

The underlying `JsonRpcOnStreamClient.readLine()` at line 78 uses `BufferedReader.readLine()` which reads until a newline. While there is a socket timeout of 2 seconds, a trickle attack (sending bytes without newlines) can keep the connection alive indefinitely.

Additionally, the executor is a **static singleton** shared across ALL `HSMClientProtocol` instances (line 44, 168-173). If one request hangs, all HSM operations across all key types (BTC, RSK, MST) are blocked.

**Exact prerequisites:**
- Same MITM/rogue HSM prerequisite as Finding 1

**Step-by-step abuse path:**
1. Attacker MITMs the HSM connection
2. On receiving any JSON-RPC request, attacker sends a partial response without a newline (e.g., `{"errorco` then trickles one byte per second)
3. `readLine()` never returns because it keeps receiving data but no newline
4. `future.get()` blocks indefinitely
5. The single-threaded executor is permanently occupied
6. All subsequent HSM operations (signing, public key retrieval, bookkeeping) queue up and never execute

**Why this is reachable in practice:**
- The socket timeout only applies to idle reads; continuous trickle data resets the timeout
- The static executor at line 44 means one stuck operation blocks the entire HSM subsystem
- No other component can bypass the blocked executor

**Realistic impact:**
- Complete HSM communication deadlock
- All signing, bookkeeping, and key retrieval operations halt
- The node cannot process peg-outs or advance the HSM's blockchain state

**Why it is NOT a false positive:**
1. ✅ `future.get()` at line 102 has no timeout parameter — verified directly
2. ✅ The executor is static and single-threaded (`Executors.newSingleThreadExecutor()`) — line 170
3. ✅ `BufferedReader.readLine()` blocks until a newline, EOF, or IOException — this is standard Java behavior
4. ✅ The socket timeout (2s) is reset by any incoming bytes — a trickle attack defeats it
5. ✅ No watchdog or health-check mechanism monitors the executor for liveness

**Minimal proof-of-concept idea:**
TCP server that accepts connections and responds with one byte per second, never sending a newline. The HSM client thread blocks forever.

**Recommended fix:**
Use `future.get(timeout, TimeUnit.MILLISECONDS)` with a reasonable timeout (e.g., 30 seconds):
```java
result = future.get(30_000, TimeUnit.MILLISECONDS);
```
Handle `TimeoutException` by cancelling the future and retrying.

---

## Suspicious Areas Reviewed but Rejected

### 1. HSM Signature Not Verified by Node (Reviewed — Rejected as externally exploitable)

**What was examined:** `PowHSMSigningClient.sign()` and `HSMSigningClientV1.sign()` accept HSM-returned (r, s) values without verifying they correspond to the message and public key. `HSMChecker.java` (diagnostic tool) performs this verification at line 92, proving the developers know how to do it — but the production path omits it.

**Why rejected:** While this is a significant defense-in-depth gap, exploiting it requires compromising the HSM itself or achieving MITM on the HSM channel. The attacker model specifies "unauthenticated external actors" — an HSM MITM requires network-level access between internal components, which places it outside the strict "unauthenticated external actor" scope. Additionally, the Bridge smart contract on RSK validates multisig signatures on-chain, providing a final check. A forged signature from one federation member would not alone authorize a peg-out (quorum is required). However, **this remains a strong recommendation** for defense-in-depth.

### 2. `fed_updateBridge()` RPC Method Without Authentication

**What was examined:** `Web3FederateImpl.java:101-104` exposes `fed_updateBridge()` on the RSK JSON-RPC interface with no authentication.

**Why rejected:** The RSK JSON-RPC server is typically bound to `localhost` by default. Calling `fed_updateBridge()` triggers `BtcToRskClient.updateBridge()` which performs idempotent operations (registering known BTC transactions, updating collections). Repeated calls cause gas expenditure but the operations themselves are safe. The method requires the RPC port to be externally exposed, which is a deployment misconfiguration rather than a code vulnerability. The impact (wasted gas) requires the attacker to have RPC access, making this a configuration concern.

### 3. Plain TCP for HSM Communication (No TLS)

**What was examined:** `SocketBasedJsonRpcClientProvider.java:80` uses `new Socket()` — no TLS, no certificate pinning, no mutual authentication.

**Why rejected as standalone finding:** While this is the enabler for Findings 1 and 2, it is not independently exploitable — it is a missing security control that broadens the attack surface for other vulnerabilities. In production deployments, the HSM is typically co-located or on a trusted network segment. However, this is the single most impactful hardening recommendation for the project.

### 4. Public Key Cache Poisoning (TOFU Model)

**What was examined:** `HSMSigningClientV1.java:52` and `PowHSMSigningClient.java:40` cache public keys on first retrieval with no pinning or verification.

**Why rejected:** Requires the same MITM/compromised-HSM precondition. The Bridge contract validates that signatures come from known federation public keys, so a poisoned cache would cause the node to compute wrong `v` recovery values, resulting in rejected (not fraudulent) transactions. This is a self-DoS rather than a fund-theft vector.

### 5. RLP State File Without Integrity Protection

**What was examined:** `BtcToRskClientFileStorageImpl.java` reads/writes state files with no HMAC or signature.

**Why rejected:** Requires local filesystem write access, which is outside the "unauthenticated external actor" scope. The Bridge contract validates all submitted proofs independently, so corrupted state files cause failed submissions rather than fund theft.

### 6. Plaintext Private Key File Storage

**What was examined:** `KeyFileHandler.java:44-56` reads private keys from unencrypted files, and `KeyFileChecker.checkFilePermissions()` is advisory-only (not enforced in the signing path).

**Why rejected:** The file-based signer is deprecated (`ECDSASignerFromFileKey.java:59`), with HSM being the recommended production configuration. Exploitation requires local file read access. While this is a real key management concern, it falls under "local developer misuse" rather than external exploitation.

### 7. Concurrency Issues in BtcToRskClient

**What was examined:** Inconsistent synchronization between `updateBridgeBtcTransactions()` (partially unsynchronized) and `onBlock()`/`onTransaction()` (synchronized).

**Why rejected:** The race conditions could cause delayed peg-in processing but cannot be weaponized by an external actor for fund theft. The Bridge contract is the ultimate trust anchor and validates all submissions independently.

### 8. Integer Overflow in Pegout Sort Comparator

**What was examined:** `BtcReleaseClient.java:294` casts `long` difference to `int`.

**Why rejected:** Requires block numbers differing by >2.1 billion, which is not realistic. Even if triggered, it would only change the order of valid pegout signing, not enable unauthorized transactions.

---

## Architecture-Level Observations

1. **Defense in depth is strong at the bridge level:** The RSK Bridge smart contract validates all submissions (proofs, signatures, block headers) independently. This means most node-level bugs result in failed/delayed operations rather than fund theft.

2. **The HSM trust boundary is the weakest architectural point:** The node-to-HSM communication channel has no authentication, encryption, or message integrity. All security relies on the network being trusted. This is the single most impactful area for hardening.

3. **The codebase has limited external attack surface:** The only externally-reachable component is the RSK JSON-RPC interface (inherited from the RSK node), which adds only the `fed_updateBridge()` method. All HSM communication is outbound-only. Bitcoin interaction uses standard P2P protocol via bitcoinj.

4. **Concurrency model needs attention:** Multiple locations use plain `HashMap`, `ArrayList`, non-volatile `boolean` flags, and partial synchronization. While none of these create security vulnerabilities exploitable by external actors, they create reliability concerns that could impact availability.
