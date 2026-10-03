// Host-compiler checks for the exact production initializer; no ESP-IDF or
// real TLS/ANCS execution is represented by this test.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createSuite, ok } from '../lib/harness.mjs';
const { test, run } = createSuite('unit/audit-ancs-forwarder.spec.mjs');
const source = readFileSync(new URL('../../docs/ancs-poc/forwarder.c', import.meta.url), 'utf8');
test('[ANCS-AUDIT-01] production initializer requires a scoped key and HTTPS and clears failed reinitialization', () => {
  const start=source.indexOf('#define FL_URL_MAX'),end=source.indexOf('esp_err_t fl_forward_notification');
  ok(start >= 0 && end > start, 'production initializer boundary exists');
  const prefix = '#include <stdbool.h>\n#include <stdio.h>\n#include <string.h>\n#include <assert.h>\n'
    + 'typedef int esp_err_t;\n#define ESP_OK 0\n#define ESP_ERR_INVALID_ARG 1\n#define ESP_ERR_INVALID_SIZE 2\n'
    + '#define ESP_LOGI(tag, ...) ((void)(tag))\n';
  const main = '\nint main(void) {\n'
    + 'const char *key="fls_0123456789abcdef0123456789abcdef0123456789abcdef";\n'
    + 'assert(fl_forwarder_init("https://example.com///",key,"provider.app")==ESP_OK);\n'
    + 'assert(s_ready && strcmp(s_worker_base_url,"https://example.com")==0 && strcmp(s_relay_key,key)==0);\n'
    + 'const char *bad[]={"http://example.com","https://","https:////","https://:443","https://user@example.com","https://example.com/path","https://example.com?secret=x","https://example.com#fragment"};\n'
    + 'for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) { assert(fl_forwarder_init(bad[i],key,"provider.app")==ESP_ERR_INVALID_ARG); assert(!s_ready && s_relay_key[0]==0); }\n'
    + 'assert(fl_forwarder_init("https://example.com","flk_0123456789abcdef0123456789abcdef","provider.app")==ESP_ERR_INVALID_ARG);\n'
    + 'assert(fl_forwarder_init("https://example.com","fls_0123456789abcdef0123456789abcdef0123456789abcdeg","provider.app")==ESP_ERR_INVALID_ARG);\n'
    + 'assert(fl_forwarder_init("https://example.com",key,"")==ESP_ERR_INVALID_ARG);\n'
    + 'assert(fl_forwarder_init("https://example.com:443",key,"provider.app")==ESP_OK);\n'
    + 'assert(fl_forwarder_init(NULL,key,"provider.app")==ESP_ERR_INVALID_ARG && !s_ready && s_relay_key[0]==0);\n'
    + 'return 0;\n}\n';
  const dir=mkdtempSync(join(tmpdir(),'fl-ancs-audit-'));
  try {
    const input=join(dir,'init.c'),binary=join(dir,'init');
    writeFileSync(input,prefix+source.slice(start,end)+main);
    execFileSync('cc',['-std=c11','-Wall','-Wextra','-Werror',input,'-o',binary],{stdio:'pipe'});
    execFileSync(binary,[],{stdio:'pipe'});
  } finally { rmSync(dir,{recursive:true,force:true}); }
});
test('[ANCS-AUDIT-02] source uses the current relay envelope and scoped header with redirects disabled', () => {
  ok(source.includes('"%s/relay"'), 'current relay endpoint');
  ok(source.includes('cJSON_AddStringToObject(root, "do", "intake")'));
  ok(source.includes('cJSON_AddObjectToObject(root, "params")'));
  ok(source.includes('cJSON_AddStringToObject(params, "text", raw_text)'));
  ok(source.includes('"X-Shortcut-Key", s_relay_key'));
  ok(!source.includes('"X-Backup-Token"'), 'full account credential is not sent');
  ok(source.includes('.disable_auto_redirect = true'));
  ok(source.includes('.crt_bundle_attach = esp_crt_bundle_attach'));
});
export const runSpec=run;
