#pragma once

#include "displayapp/apps/Apps.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"
#include "components/datetime/DateTimeController.h"
#include "utility/DirtyValue.h"
#include "displayapp/widgets/StatusIcons.h"
#include <chrono>

#include "pawn/amx.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {

      class Pawn : public Screen {
      public:
        Pawn(AppControllers& controllers);
        ~Pawn() override;

        void Refresh() override;

        void QueueError(unsigned int amx_err);
        void ShowError(unsigned int amx_err);
        void ShowError(const char* msg);

        bool OnTouchEvent(TouchEvents event) override;
        bool OnTouchEvent(uint16_t x, uint16_t y) override;

        Utility::DirtyValue<std::chrono::time_point<std::chrono::system_clock, std::chrono::minutes>> currentDateTime {};
        AppControllers& controllers;

        Widgets::StatusIcons* statusIcons = nullptr;

      private:
        AMX amx;
        int refresh_index, touch_index, gesture_index;
        lv_task_t* taskRefresh = 0;
        unsigned int queued_error = 0;

        void *header = nullptr, *datablock = nullptr, *overlaypool = nullptr;

        int LoadProgram();
        void CleanUI();
      };
    }

    template <>
    struct AppTraits<Apps::Pawn> {
      static constexpr Apps app = Apps::Pawn;
      static constexpr const char* icon = "P";

      static Screens::Screen* Create(AppControllers& controllers) {
        // sizeof(Pawn)
        return new Screens::Pawn(controllers);
      };

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      };
    };
  }
}
