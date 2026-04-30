#pragma once

#include <FreeRTOS.h>
#include <lvgl/src/lv_core/lv_obj.h>
#include <string>
#include "displayapp/screens/Screen.h"
#include "displayapp/widgets/PageIndicator.h"
#include "displayapp/apps/Apps.h"
#include "displayapp/Controllers.h"
#include "components/ble/TrainsService.h"
#include "Symbols.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {
      class Trains : public Screen {
      public:
        Trains(Pinetime::Controllers::TrainsService& trains, DisplayApp* app);

        ~Trains() override;

        void Refresh() override;
        bool OnTouchEvent(TouchEvents event) override;

      private:
        Pinetime::Controllers::TrainsService& trainsService;
        DisplayApp* app;

        lv_task_t *taskRefresh {}, *taskRequestUpdate {};
        lv_obj_t *label_status, *label_update_age, *label_time;

        bool is_connected = false;
        TickType_t updated_at = 0, time_updated_at = 0;

        void UpdateTimeLabels(const Pinetime::Controllers::TrainsService::Schedule *sched, bool force);

        /** Watchapp */
      };
    }

    template <>
    struct AppTraits<Apps::Trains> {
      static constexpr Apps app = Apps::Trains;
      static constexpr const char* icon = "T";

      static Screens::Screen* Create(AppControllers& controllers) {
        return new Screens::Trains(*controllers.trainsService, controllers.displayApp);
      };

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      };
    };
  }
}
