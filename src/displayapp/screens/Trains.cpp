#include "Trains.h"
#include "components/ble/TrainsService.h"
#include "displayapp/DisplayApp.h"
#include <libraries/log/nrf_log.h>

using namespace Pinetime::Applications::Screens;
using namespace Pinetime::Controllers;

static void printRelativeTime(int seconds, char* buffer) {
  if (seconds < 60) {
    sprintf(buffer, "%ds", seconds);
  } else if (seconds < 3600) {
    sprintf(buffer, "%dm", seconds / 60);
  } else {
    sprintf(buffer, "%dh", seconds / 3600);
  }
}

Trains::Trains(Pinetime::Controllers::TrainsService& trains, DisplayApp* app) : trainsService(trains), app(app) {
  is_connected = trains.OnOpened();

  label_status = lv_label_create(lv_scr_act(), nullptr);
  lv_label_set_text_static(label_status, is_connected ? "loading" : "not connected");
  lv_label_set_align(label_status, LV_LABEL_ALIGN_CENTER);
  lv_obj_set_width(label_status, LV_HOR_RES);
  lv_obj_align(label_status, nullptr, LV_ALIGN_CENTER, 0, 0);

  if (is_connected) {
    taskRefresh = lv_task_create(RefreshTaskCallback, LV_DISP_DEF_REFR_PERIOD, LV_TASK_PRIO_MID, this);
  }
}

Trains::~Trains() {
  if (taskRefresh)
    lv_task_del(taskRefresh);
  if (taskRequestUpdate)
    lv_task_del(taskRequestUpdate);
  lv_obj_clean(lv_scr_act());

  trainsService.OnClosed();
}

void Trains::Refresh() {
  auto sched = trainsService.GetSchedule();

  if (!sched)
    return; // No need to refresh, we don't have new data

  if (sched->isFailed) {
    if (updated_at != sched->updatedAt) {
      updated_at = sched->updatedAt;

      lv_label_set_text(label_status, "failed to\nfetch data");
      lv_obj_set_style_local_text_color(label_status, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_RED);
      lv_obj_realign(label_status);
    }

    return;
  }

  char buf[15];

  if (sched->updatedAt <= updated_at) {
    UpdateTimeLabels(sched, false);
  } else {
    updated_at = sched->updatedAt;

    lv_obj_clean(lv_scr_act());

    label_time = lv_label_create(lv_scr_act(), nullptr);
    lv_label_set_long_mode(label_time, LV_LABEL_LONG_BREAK);
    lv_label_set_align(label_time, LV_LABEL_ALIGN_CENTER);
    lv_obj_set_style_local_text_font(label_time, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, &jetbrains_mono_extrabold_compressed);
    lv_obj_set_width(label_time, LV_HOR_RES);
    lv_obj_align(label_time, nullptr, LV_ALIGN_CENTER, 0, 0);

    lv_obj_set_style_local_text_color(label_time,
                                      LV_LABEL_PART_MAIN,
                                      LV_STATE_DEFAULT,
                                      sched->nextTrainInSeconds < 5 * 60    ? LV_COLOR_RED
                                      : sched->nextTrainInSeconds < 10 * 60 ? LV_COLOR_ORANGE
                                                                            : LV_COLOR_WHITE);

    auto label_desc = lv_label_create(lv_scr_act(), nullptr);
    lv_label_set_long_mode(label_desc, LV_LABEL_LONG_BREAK);
    lv_label_set_text_fmt(label_desc, "to next train from\n%s to %s", sched->originName.get(), sched->destinationName.get());
    lv_obj_set_width(label_desc, LV_HOR_RES);
    lv_label_set_align(label_desc, LV_LABEL_ALIGN_CENTER);
    lv_obj_align(label_desc, label_time, LV_ALIGN_OUT_BOTTOM_MID, 0, 5);

    if (sched->delaySeconds > 60) {
      auto label_delay = lv_label_create(lv_scr_act(), nullptr);
      printRelativeTime(sched->delaySeconds, buf);
      lv_label_set_text_fmt(label_delay, "%s delayed", buf);
      lv_obj_set_style_local_text_opa(label_delay, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, LV_OPA_60);
      lv_obj_align(label_delay, label_time, LV_ALIGN_OUT_TOP_MID, 0, -5);
    }

    label_update_age = lv_label_create(lv_scr_act(), nullptr);
    lv_obj_set_style_local_text_color(label_update_age, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, LV_COLOR_ORANGE);
    lv_obj_align(label_update_age, nullptr, LV_ALIGN_IN_TOP_RIGHT, 0, 0);
    lv_obj_set_hidden(label_update_age, true);

    UpdateTimeLabels(sched, true);
  }
}

bool Trains::OnTouchEvent(TouchEvents event) {
  (void) event;
  return false;
}

void Pinetime::Applications::Screens::Trains::UpdateTimeLabels(const TrainsService::Schedule* sched, bool force) {
  char buf[15];

  if (!force && xTaskGetTickCount() - time_updated_at < configTICK_RATE_HZ) {
    return;
  }
  time_updated_at = xTaskGetTickCount();

  TickType_t updateAge = xTaskGetTickCount() - updated_at;
  int ageSeconds = updateAge / configTICK_RATE_HZ;
  int extrapolatedTime = sched->nextTrainInSeconds - ageSeconds;

  if (extrapolatedTime < 0) {
    // TODO: Do something
    return;
  }

  if (ageSeconds > 10) {
    lv_obj_set_hidden(label_update_age, false);

    printRelativeTime(ageSeconds, buf);
    lv_label_set_text(label_update_age, buf);
    lv_obj_realign(label_update_age);
  } else {
    lv_obj_set_hidden(label_update_age, true);
  }

  printRelativeTime(extrapolatedTime, buf);
  lv_label_set_text(label_time, buf);
  lv_obj_realign(label_time);
}
