#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_http_client.h"
#include "telegram_api.h"
#include "cJSON.h"

extern const char telegram_certificate_pem_start[] asm("_binary_telegram_certificate_pem_start");
extern const char telegram_certificate_pem_end[]   asm("_binary_telegram_certificate_pem_end");
static const char *TAG = "tgClient";
static uint8_t output_buffer[2048];
static uint8_t tempBuffer[512];
static char url_with_token[74];

static esp_http_client_handle_t client;
static esp_http_client_config_t config;

#define HTTP_BOUNDARY "skaptor"

static cJSON* cjson_root;

#define API_URL_BASE        "https://api.telegram.org/bot"
#define API_GETME           "/getMe"
#define API_GETUPDATES      "/getUpdates"
#define API_SENDMESSAGE     "/sendMessage"
#define API_SENDCHATACTION  "/sendChatAction"
#define API_SENDPHOTO       "/sendPhoto"

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

    memset(output_buffer, 0x00, sizeof(output_buffer));
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
    esp_http_client_cleanup(client);

    return status == 200 ? ESP_OK : ESP_FAIL;
}

esp_err_t telegram_api_sendMessage(uint64_t chat_id, char *message)
{
    char send_msg_url[100];
    char json_data[256];

    memset(output_buffer, 0x00, sizeof(output_buffer));
    memset(json_data, 0x00, sizeof(json_data));    
    sprintf(json_data, "{\"chat_id\": %llu,\"text\": \"%s\"}", chat_id, message);

    create_endpoint_url(send_msg_url, API_SENDMESSAGE, 100);
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

    return ESP_OK;
}

esp_err_t telegram_api_sendChatAction(uint64_t chat_id, TelegramChatAction_t action)
{
    char send_action_url[100];
    char json_data[100];

    memset(json_data, 0x00, sizeof(json_data));
    memset(output_buffer, 0x00, sizeof(output_buffer));

    sprintf(json_data, "{\"chat_id\": %llu,\"action\": \"%s\"}", chat_id, action == typing ? "typing" : "upload_photo");

    create_endpoint_url(send_action_url, API_SENDCHATACTION, 100);
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

    if (arrayItem == NULL){
        return ESP_FAIL;
    }

	cJSON *updateId = cJSON_GetObjectItemCaseSensitive(arrayItem, "update_id");
	container->update_id = updateId->valueint;

	cJSON *message = cJSON_GetObjectItemCaseSensitive(arrayItem, "message");

    if (message == NULL){
        return ESP_FAIL;
    }

	cJSON *from = cJSON_GetObjectItemCaseSensitive(message, "from");
	cJSON *text = cJSON_GetObjectItemCaseSensitive(message, "text");

	container->chat_id = cJSON_GetObjectItemCaseSensitive(from, "id")->valuedouble;
	container->first_name = cJSON_GetObjectItemCaseSensitive(from, "first_name")->valuestring;

    cJSON *last_name = cJSON_GetObjectItemCaseSensitive(from, "last_name");

    if (last_name != NULL){
	    container->last_name = last_name->valuestring;
    }

    container->message = (text != NULL) ? text->valuestring : NULL;
    container->valid = text != NULL;

    return ESP_OK;
}

esp_err_t telegram_api_getLatestMessage(TelegramMessage_t *container, uint32_t last_id)
{
    char getUpdates_url[128];
    char last_id_buffer[32];

    create_endpoint_url(getUpdates_url, API_GETUPDATES, sizeof(getUpdates_url));
    memset(output_buffer, 0x00, sizeof(output_buffer));

    //use long polling (timeout of 300s (5minutes))
    strcat(getUpdates_url, "?limit=1&timeout=300");

    if (last_id > 0){
        memset(last_id_buffer, 0x00, sizeof(last_id_buffer));
        sprintf(last_id_buffer, "&&offset=%lu", last_id);
        strcat(getUpdates_url, last_id_buffer);        
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

    err = parse_getUpdates((char *)output_buffer, container);

    return (status == 200 && err == ESP_OK) ? ESP_OK : ESP_FAIL;
}

esp_err_t telegram_api_sendPhoto(uint64_t chat_id, uint8_t *data, uint32_t size)
{
    char sendPhoto_url[128];
    char body[190];
    char tail[15] = "\r\n--skaptor--\r\n";

    create_endpoint_url(sendPhoto_url, API_SENDPHOTO, sizeof(sendPhoto_url));
    memset(output_buffer, 0x00, sizeof(output_buffer));

    sprintf(body, "--skaptor\r\nContent-Disposition: form-data; name=\"chat_id\"; \r\n\r\n%llu\r\n--skaptor\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"esp32-cam.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", chat_id);

    uint32_t length = strlen(body) + strlen(tail) + size;
    char lengthStr[10];
	sprintf(lengthStr, "%lu", length);
    ESP_LOGI(TAG, "content-length: %s", lengthStr);

    esp_http_client_set_url(client, sendPhoto_url);
    esp_http_client_set_method(client, HTTP_METHOD_POST);
    esp_http_client_set_header(client, "Content-Type", "multipart/form-data; boundary=skaptor");
    esp_http_client_set_header(client, "Content-Length", lengthStr);

    esp_http_client_close(client);
    esp_err_t err = esp_http_client_open(client, length);

    if (err != ESP_OK){
        ESP_LOGE(TAG, "unable to open client");
        return err;
    }

	esp_http_client_write(client, body, strlen(body));

    uint8_t *tmp = data;
    #define CHUNK 4096

    for (uint32_t i=0 ; i<size ; i+=CHUNK){
        if ((i + CHUNK) < size){
            ESP_LOGI(TAG, "write chunk%lu:\t%i", i, esp_http_client_write(client, (const char *)tmp, CHUNK));
            tmp += CHUNK;
            continue;
        }
        
        size_t remainder = size % CHUNK;

        if (remainder > 0) {
            ESP_LOGI(TAG, "write chunk%lu:\t%i", i, esp_http_client_write(client, (const char *)tmp, remainder));
            continue;
        }
    }

    esp_http_client_write(client, tail, strlen(tail));
    esp_http_client_fetch_headers(client);
	esp_http_client_is_chunked_response(client);

    int responseLength = esp_http_client_get_content_length(client);
	ESP_LOGI(TAG, "responseLength:\t%i", responseLength);

    int32_t status = esp_http_client_get_status_code(client);

    esp_http_client_read(client, (char *)output_buffer, responseLength);

    ESP_LOGI(TAG, "HTTP Status: %lu, contentLength: %llu", status, esp_http_client_get_content_length(client));

    err = esp_http_client_close(client);

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
