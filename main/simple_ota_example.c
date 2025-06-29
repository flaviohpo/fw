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

#include "cJSON.h"
#include "nvs.h"
#include "nvs_flash.h"
#include <sys/socket.h>
#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

// coisas do USB
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <dirent.h>
#include <inttypes.h>
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "usb/usb_host.h"
#include "usb/msc_host.h"
#include "usb/msc_host_vfs.h"
#include "ffconf.h"
#include "errno.h"

#define FW_VERSION 5
#define WIFI_CONNECTED_BIT BIT0
#define HASH_LEN 32
#define OTA_URL_SIZE 256
#define MNT_PATH "/usb"     // Path in the Virtual File System, where the USB flash drive is going to be mounted
#define BUFFER_SIZE 4096       // The read/write performance can be improved with larger buffer for the cost of RAM, 4kB is enough for most usecases

static const char *TAG = "simple_ota_example";
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");
static bool dev_present = false;

void simple_ota_example_task(void *pvParameter);
static EventGroupHandle_t wifi_event_group;
const char * URL_JSON = "https://raw.githubusercontent.com/flaviohpo/fw/refs/heads/main/meta.json";

static QueueHandle_t app_queue;
typedef struct {
    enum {
        APP_QUIT,                // Signals request to exit the application
        APP_DEVICE_CONNECTED,    // USB device connect event
        APP_DEVICE_DISCONNECTED, // USB device disconnect event
    } id;
    union {
        uint8_t new_dev_address; // Address of new USB device for APP_DEVICE_CONNECTED event if
    } data;
} app_message_t;

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

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disconn = (wifi_event_sta_disconnected_t *) event_data;
        ESP_LOGW("wifi", "Desconectado do Wi-Fi! Motivo: %d", disconn->reason);
        esp_wifi_connect();
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
    char ssid[64] = {0};
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
    //strcpy((char*) wifi_config.sta.ssid, "VIVOFIBRA-WIFI6-C100");
    //strcpy((char*) wifi_config.sta.password, "4aN9cARhgcFcd4E");
    strcpy((char*) wifi_config.sta.ssid, ssid);
    strcpy((char*) wifi_config.sta.password, pass);
    strcpy((char*) wifi_config.sta.sae_h2e_identifier, "");
    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;

    esp_log_level_set("wifi", ESP_LOG_INFO);
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    esp_wifi_set_ps(WIFI_PS_NONE);

    ESP_LOGI("wifi", "Conectando a %s...", ssid);

    EventBits_t bits = xEventGroupWaitBits(wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE, pdMS_TO_TICKS(10000));
    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI("wifi", "Wi-Fi conectado!");
    } else {
        ESP_LOGE("wifi", "Falha ao conectar no Wi-Fi");
    }

}

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

// USB
static void msc_event_cb(const msc_host_event_t *event, void *arg)
{
    if (event->event == MSC_DEVICE_CONNECTED) {
        ESP_LOGI(TAG, "MSC device connected (usb_addr=%d)", event->device.address);
        app_message_t message = {
            .id = APP_DEVICE_CONNECTED,
            .data.new_dev_address = event->device.address,
        };
        xQueueSend(app_queue, &message, portMAX_DELAY);
    } 
    else if (event->event == MSC_DEVICE_DISCONNECTED) 
    {
        ESP_LOGI(TAG, "MSC device disconnected");
        app_message_t message = {
            .id = APP_DEVICE_DISCONNECTED,
        };
        xQueueSend(app_queue, &message, portMAX_DELAY);
    }
}

static void print_device_info(msc_host_device_info_t *info)
{
    const size_t megabyte = 1024 * 1024;
    uint64_t capacity = ((uint64_t)info->sector_size * info->sector_count) / megabyte;

    printf("Device info:\n");
    printf("\t Capacity: %llu MB\n", capacity);
    printf("\t Sector size: %"PRIu32"\n", info->sector_size);
    printf("\t Sector count: %"PRIu32"\n", info->sector_count);
    printf("\t PID: 0x%04X \n", info->idProduct);
    printf("\t VID: 0x%04X \n", info->idVendor);
#ifndef CONFIG_NEWLIB_NANO_FORMAT
    wprintf(L"\t iProduct: %S \n", info->iProduct);
    wprintf(L"\t iManufacturer: %S \n", info->iManufacturer);
    wprintf(L"\t iSerialNumber: %S \n", info->iSerialNumber);
#endif
}

static void trim(char *str) {
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != str) memmove(str, start, strlen(start) + 1);
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

static void file_operations(void)
{
    const char *file_path = "/usb/wifi.txt";

    FILE *f = fopen(file_path, "r");
    if (f == NULL) {
        ESP_LOGE(TAG, "Failed to open file for reading");
        return;
    }

    char ssid[64] = {0};
    char pass[64] = {0};

    if (fgets(ssid, sizeof(ssid), f) == NULL) {
        ESP_LOGE(TAG, "Erro ao ler a primeira linha (SSID)");
        fclose(f);
        return;
    }

    if (fgets(pass, sizeof(pass), f) == NULL) {
        ESP_LOGE(TAG, "Erro ao ler a segunda linha (senha)");
        fclose(f);
        return;
    }

    fclose(f);

    // Remove quebras de linha e espaços
    ssid[strcspn(ssid, "\r\n")] = '\0';
    pass[strcspn(pass, "\r\n")] = '\0';

    trim(ssid);
    trim(pass);

    // Debug bytes
    ESP_LOGI(TAG, "SSID lido: '%s'", ssid);
    ESP_LOGI(TAG, "Senha lida: '%s'", pass);

    //save_wifi_credentials_to_nvs("VIVOFIBRA-WIFI6-C100", "4aN9cARhgcFcd4E");
    save_wifi_credentials_to_nvs(ssid, pass);
}

static void usb_task(void *args)
{
    const usb_host_config_t host_config = { .intr_flags = ESP_INTR_FLAG_LEVEL1 };
    ESP_ERROR_CHECK(usb_host_install(&host_config));

    const msc_host_driver_config_t msc_config = {
        .create_backround_task = true,
        .task_priority = 5,
        .stack_size = 4096,
        .callback = msc_event_cb,
    };
    ESP_ERROR_CHECK(msc_host_install(&msc_config));

    bool has_clients = true;
    while (true) {
        uint32_t event_flags;
        usb_host_lib_handle_events(portMAX_DELAY, &event_flags);

        // Release devices once all clients has deregistered
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_NO_CLIENTS) {
            has_clients = false;
            if (usb_host_device_free_all() == ESP_OK) {
                break;
            };
        }
        if (event_flags & USB_HOST_LIB_EVENT_FLAGS_ALL_FREE && !has_clients) {
            break;
        }
    }

    vTaskDelay(10); // Give clients some time to uninstall
    ESP_LOGI(TAG, "Deinitializing USB");
    ESP_ERROR_CHECK(usb_host_uninstall());
    vTaskDelete(NULL);
}

void read_usb_flash(void)
{
    // Criação da fila
    app_queue = xQueueCreate(5, sizeof(app_message_t));
    assert(app_queue);

    // Criação da task usb_task
    BaseType_t task_created = xTaskCreate(usb_task, "usb_task", 4096, NULL, 2, NULL);
    assert(task_created == pdPASS);

    ESP_LOGI(TAG, "Waiting for USB flash drive to be connected");

    msc_host_device_handle_t msc_device = NULL;
    msc_host_vfs_handle_t vfs_handle = NULL;
    bool msc_installed = false;
    bool should_exit = false;

    while (!should_exit) {
        app_message_t msg;
        BaseType_t received = xQueueReceive(app_queue, &msg, pdMS_TO_TICKS(10000)); // Timeout de 10 segundos

        if (received != pdTRUE) {
            // Timeout
            ESP_LOGW(TAG, "Timeout de 10 segundos aguardando mensagem");
            if (!dev_present) {
                should_exit = true;
                continue;
            }
            continue;
        }

        if (msg.id == APP_DEVICE_CONNECTED) {
            if (dev_present) {
                ESP_LOGW(TAG, "MSC já conectado. Ignorando novo dispositivo.");
                continue;
            }

            dev_present = true;
            ESP_LOGI(TAG, "Dispositivo USB conectado");

            // Instala e monta o dispositivo
            ESP_ERROR_CHECK(msc_host_install_device(msg.data.new_dev_address, &msc_device));
            msc_installed = true;

            const esp_vfs_fat_mount_config_t mount_config = {
                .format_if_mount_failed = false,
                .max_files = 3,
                .allocation_unit_size = 8192,
            };
            ESP_ERROR_CHECK(msc_host_vfs_register(msc_device, MNT_PATH, &mount_config, &vfs_handle));

            msc_host_device_info_t info;
            ESP_ERROR_CHECK(msc_host_get_device_info(msc_device, &info));
            msc_host_print_descriptors(msc_device);
            print_device_info(&info);

            // Listar arquivos no root
            ESP_LOGI(TAG, "Conteúdo do diretório /usb:");
            DIR *dh = opendir(MNT_PATH);
            if (dh) {
                struct dirent *d;
                while ((d = readdir(dh)) != NULL) {
                    printf("  %s\n", d->d_name);
                }
                closedir(dh);
            } else {
                ESP_LOGE(TAG, "Erro ao abrir diretório %s", MNT_PATH);
            }

            // Executar operações com arquivos
            file_operations();

            ESP_LOGI(TAG, "Operações concluídas. Você pode remover o pendrive.");
        }

        else if (msg.id == APP_DEVICE_DISCONNECTED) {
            ESP_LOGI(TAG, "Dispositivo desconectado");
            dev_present = false;

            if (vfs_handle) {
                ESP_ERROR_CHECK(msc_host_vfs_unregister(vfs_handle));
                vfs_handle = NULL;
            }

            if (msc_device) {
                ESP_ERROR_CHECK(msc_host_uninstall_device(msc_device));
                msc_device = NULL;
            }

            should_exit = true; // encerra o loop
        }
    }

    // Finalização segura
    if (msc_installed) {
        ESP_LOGI(TAG, "Desinstalando host MSC");
        ESP_ERROR_CHECK(msc_host_uninstall());
    }

    vQueueDelete(app_queue);
    ESP_LOGI(TAG, "read_usb_flash finalizado");
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

    // debug and security purpose
    print_nvs_stats("nvs");

    read_usb_flash();

    //save_wifi_credentials_to_nvs("VIVOFIBRA-WIFI6-C100", "4aN9cARhgcFcd4E");
    connect_wifi_from_nvs();

    // check information
    download_and_parse_json(URL_JSON);

    // user application
    ESP_LOGI(TAG, "Executando user application...");
    while(1)
    {
        vTaskDelay(1);
    }
}
