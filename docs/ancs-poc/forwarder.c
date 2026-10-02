#include "forwarder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"

#define FL_URL_MAX 256
#define FL_RELAY_KEY_MAX 96
#define FL_APP_ID_MAX 192
#define FL_RAW_MAX 4096

static const char *TAG = "FL_ANCS_FORWARD";
static char s_worker_base_url[FL_URL_MAX];
static char s_relay_key[FL_RELAY_KEY_MAX];
static char s_dispatchland_app_id[FL_APP_ID_MAX];
static bool s_ready = false;

static void copy_bounded(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_size, "%s", src);
}

esp_err_t fl_forwarder_init(const char *worker_base_url,
                            const char *relay_key,
                            const char *dispatchland_app_id)
{
    s_ready = false;
    memset(s_relay_key, 0, sizeof(s_relay_key));
    if (!worker_base_url || !worker_base_url[0] ||
        !relay_key || !relay_key[0] ||
        !dispatchland_app_id || !dispatchland_app_id[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    /* Scoped relay only; reject full backup credentials and cleartext URLs. */
    if (strncmp(worker_base_url, "https://", 8) != 0 ||
        strlen(relay_key) != 52 || strncmp(relay_key, "fls_", 4) != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    for (const char *p = relay_key + 4; *p; ++p) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f'))) return ESP_ERR_INVALID_ARG;
    }
    const char *host = worker_base_url + 8;
    if (!((*host >= 'a' && *host <= 'z') || (*host >= 'A' && *host <= 'Z') ||
          (*host >= '0' && *host <= '9'))) return ESP_ERR_INVALID_ARG;
    bool trailing_slashes = false;
    for (const char *p = host; *p; ++p) {
        if (*p == '/') { trailing_slashes = true; continue; }
        if (trailing_slashes || !((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == ':')) return ESP_ERR_INVALID_ARG;
    }

    size_t url_len = strlen(worker_base_url);
    if (url_len >= FL_URL_MAX || strlen(relay_key) >= FL_RELAY_KEY_MAX ||
        strlen(dispatchland_app_id) >= FL_APP_ID_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    copy_bounded(s_worker_base_url, sizeof(s_worker_base_url), worker_base_url);
    while (url_len > 0 && s_worker_base_url[url_len - 1] == '/') {
        s_worker_base_url[--url_len] = '\0';
    }
    copy_bounded(s_relay_key, sizeof(s_relay_key), relay_key);
    copy_bounded(s_dispatchland_app_id, sizeof(s_dispatchland_app_id), dispatchland_app_id);
    s_ready = true;

    ESP_LOGI(TAG, "forwarder configured for one ANCS app identifier");
    return ESP_OK;
}

esp_err_t fl_forward_notification(const char *app_id,
                                  const char *title,
                                  const char *subtitle,
                                  const char *message)
{
    if (!s_ready) return ESP_ERR_INVALID_STATE;
    if (!app_id) return ESP_ERR_INVALID_ARG;
    if (strcmp(app_id, s_dispatchland_app_id) != 0) return ESP_ERR_NOT_FOUND;

    const char *safe_title = title ? title : "";
    const char *safe_subtitle = subtitle ? subtitle : "";
    const char *safe_message = message ? message : "";

    char raw_text[FL_RAW_MAX];
    int n = snprintf(raw_text, sizeof(raw_text), "%s\n%s\n%s",
                     safe_title, safe_subtitle, safe_message);
    if (n < 0) return ESP_FAIL;
    if ((size_t)n >= sizeof(raw_text)) return ESP_ERR_INVALID_SIZE;

    cJSON *root = cJSON_CreateObject();
    if (!root) return ESP_ERR_NO_MEM;
    cJSON *params = cJSON_AddObjectToObject(root, "params");
    if (!params || !cJSON_AddStringToObject(root, "do", "intake") ||
        !cJSON_AddStringToObject(params, "text", raw_text)) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return ESP_ERR_NO_MEM;

    char url[FL_URL_MAX + 16];
    int url_n = snprintf(url, sizeof(url), "%s/relay", s_worker_base_url);
    if (url_n < 0 || (size_t)url_n >= sizeof(url)) {
        free(json);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 10000,
        .disable_auto_redirect = true,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        free(json);
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-Shortcut-Key", s_relay_key);
    esp_http_client_set_header(client, "X-Device-Id", "ancs-bridge");
    esp_http_client_set_post_field(client, json, strlen(json));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "FreightLogic /relay HTTP %d", status);
        if (status < 200 || status >= 300) err = ESP_FAIL;
    } else {
        ESP_LOGW(TAG, "FreightLogic forward failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    free(json);
    return err;
}
