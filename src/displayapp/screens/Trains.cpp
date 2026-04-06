#include "Trains.h"
#include "components/ble/TrainsService.h"
#include "displayapp/DisplayApp.h"
#include <libraries/log/nrf_log.h>

using namespace Pinetime::Applications::Screens;

// static void RequestUpdateTaskCallback(lv_task_t* task) {
//   static_cast<Trains*>(task->user_data)->RequestUpdate();
// }

Trains::Trains(Pinetime::Controllers::TrainsService& trains, DisplayApp* app) : trainsService(trains), app(app) {
}

Trains::~Trains() {
  lv_task_del(taskRefresh);
  if (taskRequestUpdate)
    lv_task_del(taskRequestUpdate);
  lv_obj_clean(lv_scr_act());
}

void Trains::Refresh() {
}

bool Trains::OnTouchEvent(TouchEvents event) {
  (void)event;
  return false;
}

void Trains::RequestUpdate() {
}
