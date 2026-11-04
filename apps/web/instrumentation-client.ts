// Runs before any app module in the browser. Zod 4 compiles object parsers with `new Function`
// and probes for it on the first schema it builds; under the nonce CSP (no 'unsafe-eval' in
// production) that probe is reported as a CSP violation even though zod catches the error.
// Jitless mode skips both the probe and the compiled fast path.
import { config } from "zod";

config({ jitless: true });
