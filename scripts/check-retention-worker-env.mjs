#!/usr/bin/env node
// M7 gate check (phase 11 fills it, like check-report-worker-env.mjs): the runtime services'
// env proves the retention role is least-privilege. The retention-worker holds the retention
// DB URL, the purge MinIO keys and its broker user only (no JWT secret, app Redis, api MinIO
// user, seal / signing / platform key or metrics token); no other runtime service holds the
// retention DB URL or the purge keys (the test profile legitimately does, RT27). Phase 1 stub.
console.error("check-retention-worker-env: not implemented in phase 1 (M7 phase 11 implements it)");
process.exit(2);
