# Authentication security review

## Verified architecture
Spring Security uses a stateless session policy and a custom JWT filter. BCrypt is configured. The routes `/authenticate`, `/register`, `/register-users`, and `/signing-out` are public. `/admin-user` requires ADMIN; `/normal-user` requires ADMIN or USER.

## Priority improvements
1. Protect logout: authenticate callers and derive the account identity from the security context, never an untrusted request username.
2. Harden refresh: verify session ownership, active status, cryptographic signature, refresh expiration and token binding. Use a dedicated refresh endpoint that returns rotated credentials.
3. Avoid retaining plaintext passwords in successful Authentication objects. Verify registration hashes passwords before persistence.
4. Define expiration units, token rotation, concurrent-login and revocation policy; never return stale tokens.
5. Keep JWT signing secrets out of source control and document key rotation.
6. Add integration tests for login success/failure, disabled users, roles, logout authorization, tampered JWTs, expired tokens and refresh replay.

## Implementation roadmap
- Phase 1: tests and protected logout.
- Phase 2: secure refresh and rotation.
- Phase 3: credential handling, configuration and documentation.

This is a review document, not a claim that these code fixes have been implemented or tested.
