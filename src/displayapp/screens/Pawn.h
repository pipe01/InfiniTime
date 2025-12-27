#pragma once

#include "displayapp/apps/Apps.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"

#include "pawn/amx.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {

      class Pawn : public Screen {
      public:
        Pawn();
        ~Pawn() override;

        void Refresh() override;

      private:
        AMX amx;
        int refresh_index;

        lv_task_t* taskRefresh;
      };
    }

    template <>
    struct AppTraits<Apps::Pawn> {
      static constexpr Apps app = Apps::Pawn;
      static constexpr const char* icon = "P";

      static Screens::Screen* Create(AppControllers& /*controllers*/) {
        return new Screens::Pawn();
      };

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      };
    };
  }
}
