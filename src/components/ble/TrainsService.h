#pragma once
#define min // workaround: nimble's min/max macros conflict with libstdc++
#define max
#include <host/ble_gap.h>
#undef max
#undef min
#include <optional>
#include <memory>

namespace Pinetime {
  namespace Controllers {
    class NimbleController;

    class TrainsService {
    public:
      struct Schedule 
      {
        TickType_t updatedAt;
        TickType_t nextTrainAt;
        std::unique_ptr<char[]> currentStation;
      };

      TrainsService(NimbleController& nimble);
      void Init();

      int OnCommand(struct ble_gatt_access_ctxt* ctxt);

      std::optional<const Schedule*> GetSchedule() {
        if (schedule)
          return std::make_optional(schedule.get());
        return std::nullopt;
      }

    private:
      NimbleController& nimble;

      uint16_t eventOpenedHandle {};
      std::unique_ptr<Schedule> schedule {};

      struct ble_gatt_chr_def characteristicDefinition[3];
      struct ble_gatt_svc_def serviceDefinition[2];
    };
  }
}