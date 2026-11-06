#!/usr/bin/env node
// M11 gate check (phase 13 fills it; `verify:prod`): as `docker compose config` renders the
// dev, test and prod stacks, the mail worker holds only its own settings (the `cyberlab_mail`
// DB URL, the `mail` broker user, SMTP, the mail seal private key; `enrich` + `mail` networks,
// prod `enrich` + `egress`), the egress proxy holds no secret, DB, Redis, broker or MinIO
// setting at all (`idp` + `egress`), only the api mounts the identity seal private key and joins
// `idp`, Mailpit and idp-mock are absent from prod, and prod uses the .secrets/ files (never the
// committed dev keys). Phase 1 ships this stub: it exits 2.
//   node scripts/check-identity-env.mjs
console.error("check-identity-env lands in M11 phase 13 (not implemented)");
process.exit(2);
