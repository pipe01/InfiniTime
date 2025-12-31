#pragma once

#include "displayapp/apps/Apps.h"
#include "displayapp/screens/Screen.h"
#include "displayapp/Controllers.h"
#include "components/datetime/DateTimeController.h"
#include "utility/DirtyValue.h"
#include "displayapp/widgets/StatusIcons.h"
#include <chrono>

#include "pawn/amx.h"
#include "pawn/amxpool.h"

namespace Pinetime {
  namespace Applications {
    namespace Screens {

      class Pawn : public Screen {
      public:
        struct File {
          virtual ~File() = default;

          virtual const uint8_t* GetConst() {
            return nullptr;
          }

          virtual size_t Read(uint8_t* buffer, size_t size, size_t offset) = 0;
        };

        class ConstFile : public File {
          const uint8_t* backing;
          size_t size;

        public:
          ConstFile(const uint8_t* backing, size_t size) : backing(backing), size(size) {
          }

          const uint8_t* GetConst() override {
            return backing;
          }

          size_t Read(uint8_t* buffer, size_t size, size_t offset) override {
            if (size + offset > this->size)
              return 0;
            memcpy(buffer, backing + offset, size);
            return size;
          }
        };

        class LfsFile : public File {
          Controllers::FS& fs;
          lfs_file_t file;
          bool ok;

        public:
          LfsFile(Controllers::FS& fs, const char* path) : fs(fs) {
            ok = fs.FileOpen(&file, path, LFS_O_RDONLY) == LFS_ERR_OK;
          }

          ~LfsFile() override {
            if (ok)
              fs.FileClose(&file);
          }

          size_t Read(uint8_t* buffer, size_t size, size_t offset) override {
            if (!ok)
              return 0;

            fs.FileSeek(&file, offset);
            return fs.FileRead(&file, buffer, size);
          }
        };

        Pawn(AppControllers& controllers);
        Pawn(AppControllers& controllers, std::unique_ptr<File> file);
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

        amxPool amx_pool;
        std::unique_ptr<File> file;

      private:
        AMX amx;

        int refresh_index, touch_index, gesture_index;
        lv_task_t* taskRefresh = 0;
        unsigned int queued_error = 0;

        std::unique_ptr<uint8_t[]> header, datablock, overlaypool, filecode;

        int LoadProgram();
        void CleanUI();
      };
    }

    template <>
    struct AppTraits<Apps::Pawn> {
      static constexpr Apps app = Apps::Pawn;
      static constexpr const char* icon = "P";

      static Screens::Screen* Create(AppControllers& controllers) {
        return new Screens::Pawn(controllers);
      };

      static bool IsAvailable(Pinetime::Controllers::FS& /*filesystem*/) {
        return true;
      };
    };
  }
}
