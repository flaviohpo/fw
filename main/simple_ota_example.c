#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "protocol_examples_common.h"
#include "string.h"
#ifdef CONFIG_EXAMPLE_USE_CERT_BUNDLE
#include "esp_crt_bundle.h"
#endif

#include "nvs.h"
#include "nvs_flash.h"
#include <sys/socket.h>
#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

//#include "msc_example_main.c"

#define FW_VERSION 3

void print_nvs_stats(const char* partition_label)
{
    nvs_stats_t stats;
    esp_err_t err = nvs_get_stats(partition_label, &stats);
    if (err == ESP_OK) {
        printf("NVS stats for '%s':\n", partition_label);
        printf("  Namespace count: %u\n", stats.namespace_count);
        printf("  Used entries: %u\n", stats.used_entries);
        printf("  Free entries: %u\n", stats.free_entries);
    } else {
        printf("Failed to get NVS stats: %s\n", esp_err_to_name(err));
    }
}

void simple_ota_example_task(void *pvParameter);

#define WIFI_SSID "POKEMON5G"
#define WIFI_PASS "m1m1uK1___"

#define WIFI_CONNECTED_BIT BIT0

static EventGroupHandle_t wifi_event_group;

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
        ESP_LOGW("wifi", "Wi-Fi desconectado, tentando reconectar...");
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI("wifi", "Conectado com IP: " IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

void save_wifi_credentials_to_nvs(const char *ssid, const char *pass)
{
    nvs_handle_t handle;
    esp_err_t err;

    // Abre ou cria o namespace "storage"
    err = nvs_open("storage", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_nvs", "Erro ao abrir NVS: %s", esp_err_to_name(err));
        return;
    }

    // Salva o SSID
    err = nvs_set_str(handle, "ssid", ssid);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_nvs", "Erro ao gravar SSID: %s", esp_err_to_name(err));
        nvs_close(handle);
        return;
    }

    // Salva a senha
    err = nvs_set_str(handle, "pass", pass);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_nvs", "Erro ao gravar senha: %s", esp_err_to_name(err));
        nvs_close(handle);
        return;
    }

    // Commit das mudanças
    err = nvs_commit(handle);
    if (err != ESP_OK) {
        ESP_LOGE("wifi_nvs", "Erro ao dar commit na NVS: %s", esp_err_to_name(err));
    } else {
        ESP_LOGI("wifi_nvs", "Credenciais Wi-Fi salvas com sucesso!");
    }

    nvs_close(handle);
}


void connect_wifi_from_nvs()
{
    // Inicializa NVS se ainda não
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    // Lê SSID e senha da NVS
    char ssid[32] = {0};
    char pass[64] = {0};
    size_t len;

    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READONLY, &nvs));
    len = sizeof(ssid);
    ESP_ERROR_CHECK(nvs_get_str(nvs, "ssid", ssid, &len));
    len = sizeof(pass);
    ESP_ERROR_CHECK(nvs_get_str(nvs, "pass", pass, &len));
    nvs_close(nvs);

    ESP_LOGI("wifi", "SSID da NVS: %s", ssid);

    // Inicializa pilha de rede e Wi-Fi
    ESP_ERROR_CHECK(esp_netif_init());

    esp_err_t err = esp_event_loop_create_default();
    if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(err);
    }

    esp_netif_create_default_wifi_sta();

    wifi_event_group = xEventGroupCreate();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t wifi_config = { 0 };
    strcpy((char*) wifi_config.sta.ssid, ssid);
    strcpy((char*) wifi_config.sta.password, pass);
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI("wifi", "Conectando a %s...", ssid);

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI("wifi", "Wi-Fi conectado!");
    } else {
        ESP_LOGE("wifi", "Falha ao conectar no Wi-Fi");
    }
}

const char * URL_JSON = "https://raw.githubusercontent.com/flaviohpo/fw/refs/heads/main/meta.json";
#include "cJSON.h"
void download_and_parse_json(const char *url)
{
    esp_http_client_config_t config = {
        .url = url,
        .method = HTTP_METHOD_GET,
#ifdef CONFIG_EXAMPLE_USE_CERT_BUNDLE
        .crt_bundle_attach = esp_crt_bundle_attach,
#endif
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE("json_update", "Failed to initialise HTTP connection");
        return;
    }

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE("json_update", "Failed to open HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return;
    }

    err = esp_http_client_fetch_headers(client);
    if (err < 0) {
        ESP_LOGE("json_update", "Failed to fetch headers: %s", esp_err_to_name(err));
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return;
    }

    int content_length = esp_http_client_get_content_length(client);
    if (content_length <= 0) {
        content_length = 1024; // fallback se não vier Content-Length
    }

    char *buffer = malloc(content_length + 1);
    if (!buffer) {
        ESP_LOGE("json_update", "Failed to allocate memory");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return;
    }

    int total_read = 0;
    while (1) {
        int read_len = esp_http_client_read(client, buffer + total_read, content_length - total_read);
        if (read_len <= 0) break;
        total_read += read_len;
        if (total_read >= content_length) break;
    }
    buffer[total_read] = '\0';

    ESP_LOGI("json_update", "JSON recebido: %s", buffer);

    cJSON *root = cJSON_Parse(buffer);
    if (!root) {
        ESP_LOGE("json_update", "Erro ao parsear JSON");
        free(buffer);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return;
    }

    cJSON *version_item = cJSON_GetObjectItem(root, "version");
    int version = (cJSON_IsNumber(version_item)) ? version_item->valueint : -1;

    cJSON *file_item = cJSON_GetObjectItem(root, "file");
    char *file_url = (cJSON_IsString(file_item)) ? strdup(file_item->valuestring) : NULL;

    ESP_LOGI("json_update", "Available version: %d", version);
    ESP_LOGI("json_update", "Current version: %d", FW_VERSION);
    ESP_LOGI("json_update", "URL do arquivo: %s", file_url ? file_url : "NULL");
    
    // User code
    if (FW_VERSION < version)
    {
        ESP_LOGI("json_update", "There is a new version of FW available.");
        xTaskCreate(&simple_ota_example_task, "ota_example_task", 8192, NULL, 5, NULL);
    }
    else
    {
        ESP_LOGI("json_update", "The firmware is up to date.");
    }

    cJSON_Delete(root);
    free(buffer);
    if (file_url) free(file_url);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

#define HASH_LEN 32

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
/* The interface name value can refer to if_desc in esp_netif_defaults.h */
#if CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF_ETH
static const char *bind_interface_name = EXAMPLE_NETIF_DESC_ETH;
#elif CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF_STA
static const char *bind_interface_name = EXAMPLE_NETIF_DESC_STA;
#endif
#endif

static const char *TAG = "simple_ota_example";
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id) {
    case HTTP_EVENT_ERROR:
        ESP_LOGD(TAG, "HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        ESP_LOGD(TAG, "HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_ON_DATA:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        break;
    case HTTP_EVENT_ON_FINISH:
        ESP_LOGD(TAG, "HTTP_EVENT_ON_FINISH");
        break;
    case HTTP_EVENT_DISCONNECTED:
        ESP_LOGD(TAG, "HTTP_EVENT_DISCONNECTED");
        break;
    case HTTP_EVENT_REDIRECT:
        ESP_LOGD(TAG, "HTTP_EVENT_REDIRECT");
        break;
    }
    return ESP_OK;
}

void simple_ota_example_task(void *pvParameter)
{
    ESP_LOGI(TAG, "Starting OTA example task");
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
    esp_netif_t *netif = get_example_netif_from_desc(bind_interface_name);
    if (netif == NULL) {
        ESP_LOGE(TAG, "Can't find netif from interface description");
        abort();
    }
    struct ifreq ifr;
    esp_netif_get_netif_impl_name(netif, ifr.ifr_name);
    ESP_LOGI(TAG, "Bind interface name is %s", ifr.ifr_name);
#endif
    esp_http_client_config_t config = {
        .url = CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL,
#ifdef CONFIG_EXAMPLE_USE_CERT_BUNDLE
        .crt_bundle_attach = esp_crt_bundle_attach,
#else
        .cert_pem = (char *)server_cert_pem_start,
#endif /* CONFIG_EXAMPLE_USE_CERT_BUNDLE */
        .event_handler = _http_event_handler,
        .keep_alive_enable = true,
#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_BIND_IF
        .if_name = &ifr,
#endif
    };

#ifdef CONFIG_EXAMPLE_FIRMWARE_UPGRADE_URL_FROM_STDIN
    char url_buf[OTA_URL_SIZE];
    if (strcmp(config.url, "FROM_STDIN") == 0) {
        example_configure_stdin_stdout();
        fgets(url_buf, OTA_URL_SIZE, stdin);
        int len = strlen(url_buf);
        url_buf[len - 1] = '\0';
        config.url = url_buf;
    } else {
        ESP_LOGE(TAG, "Configuration mismatch: wrong firmware upgrade image url");
        abort();
    }
#endif

#ifdef CONFIG_EXAMPLE_SKIP_COMMON_NAME_CHECK
    config.skip_cert_common_name_check = true;
#endif

    esp_https_ota_config_t ota_config = {
        .http_config = &config,
    };
    ESP_LOGI(TAG, "Attempting to download update from %s", config.url);
    esp_err_t ret = esp_https_ota(&ota_config);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "OTA Succeed, Rebooting...");
        esp_restart();
    } else {
        ESP_LOGE(TAG, "Firmware upgrade failed");
    }
    while (1) {
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

static void print_sha256(const uint8_t *image_hash, const char *label)
{
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s %s", label, hash_print);
}

static void get_sha256_of_partitions(void)
{
    uint8_t sha_256[HASH_LEN] = { 0 };
    esp_partition_t partition;

    // get sha256 digest for bootloader
    partition.address   = ESP_BOOTLOADER_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_OFFSET;
    partition.type      = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");
}

void app_main(void)
{
    ESP_LOGI(TAG, "OTA example app_main start");
    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // 1.OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // 2.NVS partition contains data in new format and cannot be recognized by this version of code.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    get_sha256_of_partitions();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    save_wifi_credentials_to_nvs(WIFI_SSID, WIFI_PASS);
    connect_wifi_from_nvs();

#if CONFIG_EXAMPLE_CONNECT_WIFI
    /* Ensure to disable any WiFi power save mode, this allows best throughput
     * and hence timings for overall OTA operation.
     */
    esp_wifi_set_ps(WIFI_PS_NONE);
#endif // CONFIG_EXAMPLE_CONNECT_WIFI

    // debug and security purpose
    print_nvs_stats("nvs");

    // check information
    download_and_parse_json(URL_JSON);

    // user application

}
