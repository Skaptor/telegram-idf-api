#ifndef TELEGRAM_API_H_
#define TELEGRAM_API_H_

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>

typedef enum TG_CHAT_ACTION
{
    typing,
    upload_photo,
    record_video,
    upload_video,
    record_voice,
    upload_voice,
    upload_document,
    choose_sticker,
    find_location,
    record_video_note,
    upload_video_note,
}TelegramChatAction_t;

typedef struct _TELEGRAM_MESSAGE_
{
    bool  valid;
	char* first_name;
	char* last_name;
	char* message;
	uint64_t update_id;
	uint64_t chat_id;
}TelegramMessage_t;

esp_err_t telegram_api_getMe(void);
esp_err_t telegram_api_sendMessage(uint64_t chat_id, char *message);
esp_err_t telegram_api_sendChatAction(uint64_t chat_id, TelegramChatAction_t action);
esp_err_t telegram_api_getLatestMessage(TelegramMessage_t *container, uint32_t last_id);
esp_err_t telegram_api_sendPhoto(uint64_t chat_id, uint8_t *data, uint32_t size);
esp_err_t telegram_api_initialize(char *bot_token);
esp_err_t telegram_api_close(void);

#endif
