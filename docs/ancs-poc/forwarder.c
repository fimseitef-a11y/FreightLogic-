#include "forwarder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_log.h"

#define FL_URL_MAX 256
#define FL_TOKEN_MAX 96
#define FL_APP_ID_MAX 192
#define FL_RAW_MAX 4096

static const char *TAG = "FL_ANCS_FORWARD";
static char s_worker_base_url[FL_URL_MAX];
static char s_driver_token[FL_TOKEN_MAX];
static char s_dispatchland_app_id[FL_APP_ID_MAX];
static bool s_ready = false;

static void copy_bounded(char *dst, size_t dst_size, const char *src)
{
    if (!dst || dst_size == 0) return;
    if (!src) src = "";
    snprintf(dst, dst_size, "%s", src);
}

esp_err_t fl_forwarder_init(const char *worker_base_url,
                            const char *driver_token,
                            const char *dispatchland_app_id)
{
    if (!worker_base_url || !worker_base_url[0] ||
        !driver_token || !driver_token[0] ||
        !dispatchland_app_id || !dispatchland_app_id[0]) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t url_len = strlen(worker_base_url);
    if (url_len >= FL_URL_MAX || strlen(driver_token) >= FL_TOKEN_MAX ||
        strlen(dispatchland_app_id) >= FL_APP_ID_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }

    copy_bounded(s_worker_base_url, sizeof(s_worker_base_url), worker_base_url);
    while (url_len > 0 && s_worker_base_url[url_len - 1] == '/') {
        s_worker_base_url[--url_len] = '\0';
    }
    copy_bounded(s_driver_token, sizeof(s_driver_token), driver_token);
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
    if (!cJSON_AddStringToObject(root, "text", raw_text)) {
        cJSON_Delete(root);
        return ESP_ERR_NO_MEM;
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!json) return ESP_ERR_NO_MEM;

    char url[FL_URL_MAX + 16];
    int url_n = snprintf(url, sizeof(url), "%s/extract", s_worker_base_url);
    if (url_n < 0 || (size_t)url_n >= sizeof(url)) {
        free(json);
        return ESP_ERR_INVALID_SIZE;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .method = HTTP_METHOD_POST,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        free(json);
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "X-Backup-Token", s_driver_token);
    esp_http_client_set_header(client, "X-Device-Id", "ancs-bridge");
    esp_http_client_set_post_field(client, json, strlen(json));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        ESP_LOGI(TAG, "FreightLogic /extract HTTP %d", status);
        if (status < 200 || status >= 300) err = ESP_FAIL;
    } else {
        ESP_LOGW(TAG, "FreightLogic forward failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    free(json);
    return err;
}
