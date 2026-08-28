#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Configure the FreightLogic ANCS proof-of-concept forwarder.
 *
 * worker_base_url: e.g. https://<worker-host> (no trailing slash)
 * driver_token: current FreightLogic X-Backup-Token for smoke testing only
 * dispatchland_app_id: actual App Identifier observed from ANCS; never guess it
 */
esp_err_t fl_forwarder_init(const char *worker_base_url,
                            const char *driver_token,
                            const char *dispatchland_app_id);

/**
 * Forward a fully assembled ANCS notification to FreightLogic /extract.
 * Returns ESP_ERR_NOT_FOUND when app_id does not match the configured
 * DispatchLand App Identifier.
 */
esp_err_t fl_forward_notification(const char *app_id,
                                  const char *title,
                                  const char *subtitle,
                                  const char *message);

#ifdef __cplusplus
}
#endif
