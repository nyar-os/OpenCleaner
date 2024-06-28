import { defineConfig } from '@vmz/vmz';

/**
 * WebView2 host loads local static HTML under packages/open-cleaner/dist/gui.
 * Builtin profile `static` → assembly `web-static`.
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
