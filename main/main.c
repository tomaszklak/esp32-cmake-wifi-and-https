/* Hello World Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <esp_idf_sys_wifi_and_https.h>

void app_main(void) {
    printf("Hello world from C!\n");

    int result = run_wifi_https_and_wireguard();

    printf("Rust returned code: %d\n", result);
}
