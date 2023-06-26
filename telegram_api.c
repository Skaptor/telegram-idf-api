#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

#include "cJSON.h"

#include "telegram_api.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_http_client.h"

extern const char telegram_certificate_pem_start[] asm("_binary_telegram_certificate_pem_start");
extern const char telegram_certificate_pem_end[]   asm("_binary_telegram_certificate_pem_end");
static const char *TAG = "tgClient";
static uint8_t output_buffer[2048];
static uint8_t tempBuffer[512];
static char url_with_token[74];

static esp_http_client_handle_t client;
static esp_http_client_config_t config;

static cJSON* cjson_root;

#define API_URL_BASE        "https://api.telegram.org/bot"
#define API_GETME           "/getMe"
#define API_GETUPDATES      "/getUpdates"
#define API_SENDMESSAGE     "/sendMessage"
#define API_SENDCHATACTION  "/sendChatAction"

static esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    static int output_len;

    switch(evt->event_id)
    {
        default:                        ESP_LOGD(TAG, "HTTP_EVENT_DEFAULT ");       break;
        case HTTP_EVENT_ERROR:          ESP_LOGD(TAG, "HTTP_EVENT_ERROR");          break;
        case HTTP_EVENT_ON_CONNECTED:   ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");   break;
        case HTTP_EVENT_HEADER_SENT:    ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");    break;
        case HTTP_EVENT_ON_HEADER:      ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);    break;
        case HTTP_EVENT_ON_DATA:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);

            if (evt->user_data != NULL){
                memcpy(evt->user_data + output_len, evt->data, evt->data_len);
                output_len += evt->data_len;
                break;
            }

            output_len = 0;
            memcpy(tempBuffer + output_len, evt->data, evt->data_len);
            output_len += evt->data_len;
            break;

        case HTTP_EVENT_ON_FINISH:
            ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
            output_len = 0;
            break;

        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);

            if (err != 0) {
                output_len = 0;
                ESP_LOGI(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGI(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            break;
    }
    return ESP_OK;
}

static void create_endpoint_url(char *buffer, char *endpoint, uint8_t buffer_size)
{
    memset(buffer, 0x00, buffer_size);
    strcat(buffer, url_with_token);
    strcat(buffer, endpoint);
    ESP_LOGI(TAG, "endpoint: %s", buffer);
}

esp_err_t telegram_api_getMe(void)
{
    char getme_url[100];

    create_endpoint_url(getme_url, API_GETME, 100);

    client = esp_http_client_init(&config);
    esp_http_client_set_url(client, getme_url);
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Content-Type", "x-www-form-urlencoded");

    esp_err_t err = esp_http_client_perform(client);

    if (err != ESP_OK){
        ESP_LOGE(TAG, "Client failed. %s", esp_err_to_name(err));
        //TODO: handle cleanup when this fails
        return err;
    }

    uint32_t status = esp_http_client_get_status_code(client);

    ESP_LOGI(TAG, "HTTP Status: %lu, contentLength: %llu", status, esp_http_client_get_content_length(client));
    ESP_LOGI(TAG, "output: %s", output_buffer);
    esp_http_client_cleanup(client);

    return status == 200 ? ESP_OK : ESP_FAIL;
}

esp_err_t telegram_api_sendMessage(uint32_t chat_id, char *message)
{
    char send_msg_url[100];
    char json_data[256];

    memset(json_data, 0x00, sizeof(json_data));
    sprintf(json_data, "{\"chat_id\": %lu,\"text\": \"%s\"}", chat_id, message);

    create_endpoint_url(send_msg_url, API_SENDMESSAGE, 100);
    //client = esp_http_client_init(&config);
    esp_http_client_set_timeout_ms(client, 5000);
    esp_http_client_set_url(client, send_msg_url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_data, strlen(json_data));

    esp_err_t err = esp_http_client_perform(client);

    if (err != ESP_OK){
        ESP_LOGE(TAG, "Client failed. %s", esp_err_to_name(err));
        //TODO: handle cleanup when this fails
        return err;
    }

    uint32_t status = esp_http_client_get_status_code(client);

    ESP_LOGI(TAG, "HTTP Status: %lu, contentLength: %llu", status, esp_http_client_get_content_length(client));
    ESP_LOGI(TAG, "output: %s", output_buffer);
    //esp_http_client_cleanup(client);

    return ESP_OK;
}

esp_err_t telegram_api_sendChatAction(uint32_t chat_id, TelegramChatAction_t action)
{
    char send_action_url[100];
    char json_data[100];

    memset(json_data, 0x00, sizeof(json_data));

    sprintf(json_data, "{\"chat_id\": %lu,\"action\": \"%s\"}", chat_id, action == typing ? "typing" : "upload_photo");

    create_endpoint_url(send_action_url, API_SENDCHATACTION, 100);
    // client = esp_http_client_init(&config);
    esp_http_client_set_timeout_ms(client, 5000);
    esp_http_client_set_url(client, send_action_url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, json_data, strlen(json_data));

    esp_err_t err = esp_http_client_perform(client);

    if (err != ESP_OK){
        ESP_LOGE(TAG, "Client failed. %s", esp_err_to_name(err));
        //TODO: handle cleanup when this fails
        return err;
    }

    uint32_t status = esp_http_client_get_status_code(client);

    ESP_LOGI(TAG, "HTTP Status: %lu, contentLength: %llu", status, esp_http_client_get_content_length(client));
    ESP_LOGI(TAG, "output: %s", output_buffer);
    // esp_http_client_cleanup(client);

    return ESP_OK;
}

static esp_err_t parse_getUpdates(char *str, TelegramMessage_t *container)
{
    if (container == NULL){
        return ESP_FAIL;
    }

    container->valid = false;

	if (cjson_root != NULL) {
		cJSON_Delete(cjson_root);
	}

	cjson_root = cJSON_Parse(str);
	cJSON *ret = cJSON_GetObjectItemCaseSensitive(cjson_root, "ok");

	if (ret == NULL || ret->valueint == 0) {
        ESP_LOGE(TAG, "server response invalid");
		return ESP_FAIL;
	}

	cJSON *result = cJSON_GetObjectItemCaseSensitive(cjson_root, "result");

	if (result->type != cJSON_Array) {
        ESP_LOGE(TAG, "no data available");
		return ESP_FAIL;
	}

	if (cJSON_GetArraySize(result) == 0) {
		ESP_LOGE(TAG, "empty array, abort");
		return ESP_FAIL;
	}

	cJSON* arrayItem = cJSON_GetArrayItem(result, 0);
	cJSON *updateId = cJSON_GetObjectItemCaseSensitive(arrayItem, "update_id");
	cJSON *message = cJSON_GetObjectItemCaseSensitive(arrayItem, "message");
	cJSON *from = cJSON_GetObjectItemCaseSensitive(message, "from");
	cJSON *text = cJSON_GetObjectItemCaseSensitive(message, "text");

	container->update_id = updateId->valueint;
	container->chat_id = cJSON_GetObjectItemCaseSensitive(from, "id")->valueint;
	container->first_name = cJSON_GetObjectItemCaseSensitive(from, "first_name")->valuestring;
	container->last_name = cJSON_GetObjectItemCaseSensitive(from, "last_name")->valuestring;
	container->message = text->valuestring;
    container->valid = true;

    return ESP_OK;
}

esp_err_t telegram_api_getLatestMessage(TelegramMessage_t *container, uint32_t last_id)
{
    char getUpdates_url[128];
    char last_id_buffer[32];

    create_endpoint_url(getUpdates_url, API_GETUPDATES, sizeof(getUpdates_url));

    //use long polling (timeout of 300s (5minutes))
    strcat(getUpdates_url, "?limit=1&timeout=300");

    if (last_id > 0){
        memset(last_id_buffer, 0x00, sizeof(last_id_buffer));
        sprintf(last_id_buffer, "&&offset=%lu", last_id);
        strcat(getUpdates_url, last_id_buffer);
        ESP_LOGI(TAG, "Append: %s", last_id_buffer);
    }

    esp_http_client_set_timeout_ms(client, 301000);
    esp_http_client_set_url(client, getUpdates_url);
    esp_http_client_set_method(client, HTTP_METHOD_GET);
    esp_http_client_set_header(client, "Content-Type", "application/json");

    esp_err_t err = esp_http_client_perform(client);

    if (err != ESP_OK){
        ESP_LOGE(TAG, "Client failed. %s", esp_err_to_name(err));
        return err;
    }

    uint32_t status = esp_http_client_get_status_code(client);

    ESP_LOGI(TAG, "HTTP Status: %lu, contentLength: %llu", status, esp_http_client_get_content_length(client));
    ESP_LOGI(TAG, "output: %s", output_buffer);

    err = parse_getUpdates((char *)output_buffer, container);

    return (status == 200 && err == ESP_OK) ? ESP_OK : ESP_FAIL;
}

esp_err_t telegram_api_initialize(char *bot_token)
{
    if (strlen(bot_token) != 46){
        ESP_LOGE(TAG, "bot token must be 46 characters!");
        return ESP_FAIL;
    }

    strcat(url_with_token, API_URL_BASE);
    strcat(url_with_token, bot_token);

    memset(output_buffer, 0x00, sizeof(output_buffer));

    config.url = "https://api.telegram.org";
    config.transport_type = HTTP_TRANSPORT_OVER_SSL;
    config.event_handler = _http_event_handler;
    config.keep_alive_enable = true;    
    config.cert_pem = telegram_certificate_pem_start;
    config.user_data = output_buffer;

    ESP_LOGI(TAG, "Initializing telegram client");
    ESP_LOGI(TAG, "base url: %s", url_with_token);

    client = esp_http_client_init(&config);

    return ESP_OK;
}

esp_err_t telegram_api_close(void)
{
    esp_http_client_cleanup(client);
    return ESP_OK;
}
