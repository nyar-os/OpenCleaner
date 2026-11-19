import { defineConfig } from '@vmz/vmz';

/**
 * Static product site: profile `static` → assembly `web-static`.
 * Routes are file-based under `src/pages`.
 */
export default defineConfig({
    delivery: {
        default: 'static',
        profiles: {
            static: {
                host: 'browser',
                assembly: 'web-static',
            },
        },
    },
});
