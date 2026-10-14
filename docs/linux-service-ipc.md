# Downstream Linux service IPC policy

This fork offers an opt-in **build-time** policy for a service that needs to
listen on local Unix stream sockets. For example, OpenClaw 2026.10.3 uses them
for its native worker broker and subprocess output. This is a downstream
extension, not an upstream sandbox-runtime feature or a path allowlist.

On the Linux build host, run:

```sh
SRT_ALLOW_UNIX_STREAM=1 bun vendor/seccomp/build.ts
```

Without that setting the original strict Unix socket policy remains. Setting it
in a running workload cannot change the compiled filter. Deploy the generated
architecture-specific helper with the matching runtime; do not publish the
relaxed binary as a default upstream helper.

The policy permits `socket(AF_UNIX, SOCK_STREAM, ...)`, including CLOEXEC and
NONBLOCK flags. Other Unix socket types remain denied by `socket()`; existing
`socketpair()` and inherited-descriptor behavior is unchanged. AF_VSOCK and
io_uring denials and the separate namespace/mount filter are unchanged. The
helper still performs its normal PID/user/mount isolation and fails closed on
setup errors. Do not enable `allowAllUnixSockets` to obtain this behavior: that
option skips the helper in this revision.

## Security boundary

**Every reachable Unix stream endpoint is accessible**, including abstract
addresses and passing file descriptors with SCM_RIGHTS. This cannot distinguish
a worker socket from a privileged Docker daemon, SSH agent or network proxy.
Use only in a dedicated container with a private network namespace and curated
mounts, without privileged host sockets or descriptors. Abstract sockets share
the container network namespace. All processes inside that boundary must be
treated as sharing it; this does not isolate individual application agents.

Do not use this policy where SRT's Unix proxy sockets enforce network filtering.
The intended service uses its container's existing networking without SRT
network restrictions. Preserve capability drops, no-new-privileges, read-only
system mounts and the remaining sandbox controls. Review every mount/network
change against these assumptions. Passing regression tests is not a security
audit or a guarantee against kernel vulnerabilities.

## Regression test

With Linux x86_64 or aarch64, Python 3, gcc and libseccomp development headers:

```sh
python3 test/sandbox/unix-stream-policy.py
```

The test compiles strict and IPC variants, installs their actual BPF filters in
separate child processes and checks all low-four-bit socket types, common flags,
independent upper register bits, VSOCK and io_uring denial, pathname/abstract
stream round trips, and runtime-environment independence. It also checks that
the namespace filter is byte-identical. An outer container filter may deny
upper-bit encodings; it must never allow an operation this policy denies.
Run the existing namespace/lifecycle tests and deployment-level mount/capability
checks separately. This revision was exercised on Linux x86_64; an aarch64 run
is still required before deploying that architecture.
