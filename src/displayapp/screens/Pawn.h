#pragma once

#include "displayapp/apps/Apps.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"
#include "components/datetime/DateTimeController.h"
#include "utility/DirtyValue.h"
#include <chrono>

#include "pawn/amx.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {

      class Pawn : public Screen {
      public:
        Pawn(Controllers::DateTime& dateTimeController);
        ~Pawn() override;

        void Refresh() override;


        Utility::DirtyValue<std::chrono::time_point<std::chrono::system_clock, std::chrono::minutes>> currentDateTime {};
        Controllers::DateTime& dateTimeController;

      private:
        AMX amx;
        int refresh_index;
        lv_task_t* taskRefresh = 0;
      };
    }

    template <>
    struct AppTraits<Apps::Pawn> {
      static constexpr Apps app = Apps::Pawn;
      static constexpr const char* icon = "P";

      static Screens::Screen* Create(AppControllers& controllers) {
        return new Screens::Pawn(controllers.dateTimeController);
      };

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      };
    };
  }
}
