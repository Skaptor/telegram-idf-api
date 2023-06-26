idf_component_register(SRCS "telegram_api.c" 
                    INCLUDE_DIRS "include" REQUIRES esp_http_client esp-tls json
                    EMBED_TXTFILES telegram_certificate.pem)