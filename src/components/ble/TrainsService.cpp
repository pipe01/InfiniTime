#include "TrainsService.h"

#include <libraries/log/nrf_log.h>
#include "components/ble/NimbleController.h"

namespace {
  // 0007yyxx-78fc-48fe-8e23-433b3a1942d0
  constexpr ble_uuid128_t CharUuid(uint8_t x, uint8_t y) {
    return ble_uuid128_t {.u = {.type = BLE_UUID_TYPE_128},
                          .value = {0xd0, 0x42, 0x19, 0x3a, 0x3b, 0x43, 0x23, 0x8e, 0xfe, 0x48, 0xfc, 0x78, x, y, 0x07, 0x00}};
  }

  // 00070000-78fc-48fe-8e23-433b3a1942d0
  constexpr ble_uuid128_t BaseUuid() {
    return CharUuid(0x00, 0x00);
  }

  constexpr ble_uuid128_t trainsUuid {BaseUuid()};

  constexpr ble_uuid128_t trainsOpenUuid {CharUuid(0x01, 0x00)};
  constexpr ble_uuid128_t trainsScheduleUuid {CharUuid(0x01, 0x00)};

  int TrainsCallback(uint16_t /*conn_handle*/, uint16_t /*attr_handle*/, struct ble_gatt_access_ctxt* ctxt, void* arg) {
    return static_cast<Pinetime::Controllers::TrainsService*>(arg)->OnCommand(ctxt);
  }
} // namespace

Pinetime::Controllers::TrainsService::TrainsService(NimbleController& nimble) : nimble(nimble) {
  characteristicDefinition[0] = {.uuid = &trainsScheduleUuid.u, .access_cb = TrainsCallback, .arg = this, .flags = BLE_GATT_CHR_F_WRITE};
  characteristicDefinition[1] = {.uuid = &trainsOpenUuid.u,
                                 .access_cb = TrainsCallback,
                                 .arg = this,
                                 .flags = BLE_GATT_CHR_F_NOTIFY,
                                 .val_handle = &eventOpenedHandle};
  characteristicDefinition[2] = {0};

  serviceDefinition[0] = {.type = BLE_GATT_SVC_TYPE_PRIMARY, .uuid = &trainsUuid.u, .characteristics = characteristicDefinition};
  serviceDefinition[1] = {0};
}

void Pinetime::Controllers::TrainsService::Init() {
  uint8_t res = 0;
  res = ble_gatts_count_cfg(serviceDefinition);
  ASSERT(res == 0);

  res = ble_gatts_add_svcs(serviceDefinition);
  ASSERT(res == 0);
}

std::unique_ptr<char[]> read_string(uint8_t** ptr) {
  uint8_t label_len = *((*ptr)++);
  auto str = std::make_unique<char[]>(label_len + 1);
  memcpy(str.get(), ptr, label_len);
  str.get()[label_len] = 0;
  ptr += label_len;

  return str;
}

int Pinetime::Controllers::TrainsService::OnCommand(ble_gatt_access_ctxt* ctxt) {
  if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
    size_t bufferSize = OS_MBUF_PKTLEN(ctxt->om);

    uint8_t data[bufferSize];
    os_mbuf_copydata(ctxt->om, 0, bufferSize, data);

    if (ble_uuid_cmp(ctxt->chr->uuid, &trainsScheduleUuid.u) == 0) {
      uint8_t* ptr = data;

      uint16_t secondsUntilNext = ptr[0] | (ptr[1] << 8);
      ptr += 2;

      auto current_station = read_string(&ptr);

      schedule = std::make_unique<Schedule>((Schedule) {
        .updatedAt = xTaskGetTickCount(),
        .nextTrainAt = xTaskGetTickCount() + pdMS_TO_TICKS((TickType_t) secondsUntilNext * 1000),
        .currentStation = std::move(current_station),
      });
    }
  }

  return 0;
}
