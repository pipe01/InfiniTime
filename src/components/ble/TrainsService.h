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
      enum Destination {
        Home,
        Work,
      };

      struct Schedule {
        bool isFailed;
        TickType_t updatedAt;
        uint16_t nextTrainInSeconds, delaySeconds;
        std::unique_ptr<char[]> originName, destinationName;
      };

      TrainsService(NimbleController& nimble);
      void Init();

      bool OnOpened();

      void OnClosed() {
        schedule.reset();
      }

      int OnCommand(struct ble_gatt_access_ctxt* ctxt);

      const Schedule* GetSchedule() {
        if (schedule)
          return schedule.get();
        return nullptr;
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