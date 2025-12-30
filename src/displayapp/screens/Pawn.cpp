#include "Pawn.h"
#include <stdio.h>
#include <charconv>

extern "C" {
#include "pawn/amxpool.h"
}

#include "program.h"

using namespace Pinetime::Applications::Screens;

enum {
  PAWN_ERR_PARAMCOUNT = 100,
  PAWN_ERR_MISSINGHANDLER,
  PAWN_ERR_INVALIDSTRING,

  PAWN_ERR_FIRST = PAWN_ERR_PARAMCOUNT,
};

#define ASSERT_PARAMS(n)                                                                                                                   \
  if (params[0] != n * sizeof(cell)) {                                                                                                     \
    amx_RaiseError(amx, PAWN_ERR_PARAMCOUNT);                                                                                              \
    return 0;                                                                                                                              \
  }

#define PARAMS_OBJ(i) ((lv_obj_t*) params[i])

#define PAWN_INST ((Pawn*) amx->userdata[0])

constexpr int max_overlay_size = 512;

static void event_handler(lv_obj_t* obj, lv_event_t event) {
  if (event == LV_EVENT_DELETE)
    return;

  AMX* amx = (AMX*) lv_obj_get_user_data(lv_scr_act());
  int handler_index = (int) lv_obj_get_user_data(obj);

  amx_Push(amx, event);
  int result = amx_Exec(amx, nullptr, handler_index);
  if (result != AMX_ERR_NONE) {
    PAWN_INST->QueueError(result);
  }
}

static cell AMX_NATIVE_CALL F_lv_scr_act(AMX* amx, const cell* params) {
  ASSERT_PARAMS(0);

  return (cell) lv_scr_act();
}

static cell AMX_NATIVE_CALL F_lv_label_create(AMX* amx, const cell* params) {
  ASSERT_PARAMS(2);

  return (cell) lv_label_create(PARAMS_OBJ(1) ?: lv_scr_act(), PARAMS_OBJ(2));
}

static cell AMX_NATIVE_CALL F_lv_btn_create(AMX* amx, const cell* params) {
  ASSERT_PARAMS(2);

  return (cell) lv_btn_create(PARAMS_OBJ(1) ?: lv_scr_act(), PARAMS_OBJ(2));
}

static cell AMX_NATIVE_CALL F_lv_obj_set_pos(AMX* amx, const cell* params) {
  ASSERT_PARAMS(3);

  lv_obj_set_pos(PARAMS_OBJ(1), params[2], params[3]);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_size(AMX* amx, const cell* params) {
  ASSERT_PARAMS(3);

  lv_obj_set_size(PARAMS_OBJ(1), params[2], params[3]);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_event_cb(AMX* amx, const cell* params) {
  ASSERT_PARAMS(2);

  lv_obj_t* obj = PARAMS_OBJ(1);

  char* name;
  amx_StrParam_Type(amx, params[2], name, char*);
  if (name != NULL) {
    int index;
    if (amx_FindPublic(amx, name, &index) == AMX_ERR_NONE) {
      lv_obj_set_user_data(obj, (void*) index);
      lv_obj_set_event_cb(obj, event_handler);
    } else {
      amx_RaiseError(amx, PAWN_ERR_MISSINGHANDLER);
    }
  }

  return 0;
}

static cell AMX_NATIVE_CALL F_lv_label_set_text(AMX* amx, const cell* params) {
  ASSERT_PARAMS(2);

  lv_obj_t* label = PARAMS_OBJ(1);

  char* text;
  amx_StrParam_Type(amx, params[2], text, char*);
  if (text != NULL)
    lv_label_set_text(label, text);
  else
    amx_RaiseError(amx, PAWN_ERR_INVALIDSTRING);

  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_style_local_int(AMX* amx, const cell* params) {
  ASSERT_PARAMS(5);

  lv_obj_t* obj = PARAMS_OBJ(1);
  cell prop = params[2];
  cell value = params[3];
  cell part = params[4];
  cell state = params[5];

  _lv_obj_set_style_local_int(obj, part, prop | (state << LV_STYLE_STATE_POS), value);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_style_local_color(AMX* amx, const cell* params) {
  ASSERT_PARAMS(5);

  lv_obj_t* obj = PARAMS_OBJ(1);
  cell prop = params[2];
  cell value = params[3];
  cell part = params[4];
  cell state = params[5];

  _lv_obj_set_style_local_color(obj, part, prop | (state << LV_STYLE_STATE_POS), lv_color_hex(value));
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_style_local_opa(AMX* amx, const cell* params) {
  ASSERT_PARAMS(5);

  lv_obj_t* obj = PARAMS_OBJ(1);
  cell prop = params[2];
  cell value = params[3];
  cell part = params[4];
  cell state = params[5];

  _lv_obj_set_style_local_opa(obj, part, prop | (state << LV_STYLE_STATE_POS), value);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_style_local_ptr(AMX* amx, const cell* params) {
  ASSERT_PARAMS(5);

  lv_obj_t* obj = PARAMS_OBJ(1);
  cell prop = params[2];
  cell* value = amx_Address(amx, params[3]);
  cell part = params[4];
  cell state = params[5];

  _lv_obj_set_style_local_ptr(obj, part, prop | (state << LV_STYLE_STATE_POS), (void*) value);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_align(AMX* amx, const cell* params) {
  ASSERT_PARAMS(5)

  lv_obj_t* obj = PARAMS_OBJ(1);
  lv_obj_t* base = PARAMS_OBJ(2);
  cell align = params[3];
  cell x_ofs = params[4];
  cell y_ofs = params[5];

  lv_obj_align(obj, base, align, x_ofs, y_ofs);
  return 0;
}

static cell AMX_NATIVE_CALL F_lv_obj_realign(AMX* amx, const cell* params) {
  ASSERT_PARAMS(1)
  lv_obj_realign(PARAMS_OBJ(1));
  return 0;
}

/**
 * Hand-written implementation of sprintf with limited functionality in order to support reading strings from parameters.
 * Supported interpolations:
 *   %%
 *   %d and %x, including padding flags
 *   %s with packed strings
 */
static cell AMX_NATIVE_CALL F_sprintf(AMX* amx, const cell* params) {
  // param[0] is the number of total parameter bytes, divide it by cell size to get the parameter count
  int args_count = params[0] / sizeof(cell);
  if (args_count < 4) {
    amx_RaiseError(amx, PAWN_ERR_PARAMCOUNT);
    return 0;
  }

  cell* output = amx_Address(amx, params[1]);
  cell max_size = params[2] * sizeof(cell); // We assume the output array is packed so each cell contains one character per byte
  // TODO: add a separate sprintf_unpacked function?

  char buf[max_size];
  char* bufc = buf;
  char* bufmax = buf + max_size - 1;

  char* fmt;
  amx_StrParam_Type(amx, params[3], fmt, char*);
  if (fmt == NULL) {
    amx_RaiseError(amx, PAWN_ERR_INVALIDSTRING);
    return 0;
  }

  size_t paramc = 4;

  size_t fmt_len = strlen(fmt);
  bool in_pc = false;

  char flags[4];
  size_t flagc = 0;

  for (size_t i = 0; i < fmt_len; i++) {
    char c = fmt[i];

    if (c == '%') {
      if (in_pc) {
        *bufc++ = '%';
        in_pc = false;
      } else {
        flagc = 0;
        in_pc = true;
      }
    } else if (in_pc) {
      switch (c) {
        case 'x':
        case 'd': {
          int padding = 0;
          char pad = ' ';

          if (flagc == 1) {
            padding = flags[0] - '0';
          } else if (flagc == 2) {
            pad = flags[0];
            padding = flags[1] - '0';
          }

          std::to_chars_result result = std::to_chars(bufc, bufmax, (int) *amx_Address(amx, params[paramc++]), c == 'x' ? 16 : 10);

          int padlen = padding - (result.ptr - bufc);
          for (int n = 0; n < padlen && bufc < bufmax; n++) {
            bufc[1] = bufc[0];
            bufc[0] = pad;
            bufc++;
          }

          bufc = result.ptr + (padlen > 0 ? padlen : 0);
          in_pc = false;
          break;
        }

        case 's': {
          cell param = params[paramc++];
          int len;
          amx_StrLen(amx_Address(amx, param), &len);

          if (len > 0 && bufc + len < bufmax - 1) {
            amx_GetString(bufc, amx_Address(amx, param), 0, len + 1);
            bufc += len;
          }
          in_pc = false;
          break;
        }

        default:
          if (flagc < sizeof(flags))
            flags[flagc++] = c;
          break;
      }
    } else {
      *bufc++ = c;
    }
  }
  *bufc = 0;

  amx_SetString(output, buf, 1, 0, max_size);

  return bufc - buf;
}

static cell AMX_NATIVE_CALL F_get_datetime(AMX* amx, const cell* params) {
  ASSERT_PARAMS(1);

  Pawn* pawn = PAWN_INST;

  pawn->currentDateTime = std::chrono::time_point_cast<std::chrono::minutes>(pawn->controllers.dateTimeController.CurrentDateTime());

  cell* ret = amx_Address(amx, params[1]);

  ret[0] = pawn->currentDateTime.IsUpdated();
  ret[1] = pawn->controllers.dateTimeController.Seconds();
  ret[2] = pawn->controllers.dateTimeController.Minutes();
  ret[3] = pawn->controllers.dateTimeController.Hours();
  ret[4] = pawn->controllers.dateTimeController.Day();
  ret[5] = pawn->controllers.dateTimeController.Year();

  return 0;
}

static cell AMX_NATIVE_CALL F_get_datetime_short_str(AMX* amx, const cell* params) {
  ASSERT_PARAMS(2);

  Pawn* pawn = PAWN_INST;

  cell* ret_day = amx_Address(amx, params[1]);
  cell* ret_month = amx_Address(amx, params[2]);

  if (ret_day != NULL) {
    const char* day = pawn->controllers.dateTimeController.DayOfWeekShortToString();
    amx_SetString(ret_day, day, true, false, 4);
  }
  if (ret_month != NULL) {
    const char* month = pawn->controllers.dateTimeController.MonthShortToString();
    amx_SetString(ret_month, month, true, false, 4);
  }

  return 0;
}

static cell AMX_NATIVE_CALL F_status_icons_create(AMX* amx, const cell*) {
  Pawn* pawn = PAWN_INST;

  if (pawn->statusIcons == nullptr) {
    pawn->statusIcons = new Pinetime::Applications::Widgets::StatusIcons(pawn->controllers.batteryController,
                                                                         pawn->controllers.bleController,
                                                                         pawn->controllers.alarmController);
    pawn->statusIcons->Create();
  }

  return 0;
}

static cell AMX_NATIVE_CALL F_status_icons_update(AMX* amx, const cell*) {
  Pawn* pawn = PAWN_INST;

  if (pawn->statusIcons != nullptr)
    pawn->statusIcons->Update();

  return 0;
}

static cell AMX_NATIVE_CALL F_raise_error(AMX* amx, const cell* params) {
  ASSERT_PARAMS(1);

  amx_RaiseError(amx, params[1]);

  return 0;
}

static int AMXAPI prun_Overlay(AMX* amx, int index) {
  AMX_HEADER* hdr;
  AMX_OVERLAYINFO* tbl;

  hdr = (AMX_HEADER*) amx->base;
  tbl = (AMX_OVERLAYINFO*) (amx->base + hdr->overlays) + index;

  amx->codesize = tbl->size;
  amx->code = (unsigned char*) amx_poolfind(&PAWN_INST->amx_pool, index);

  if (amx->code == NULL) {
    if ((amx->code = (unsigned char*) amx_poolalloc(&PAWN_INST->amx_pool, tbl->size, index)) == NULL)
      return AMX_ERR_OVERLAY;

    memcpy(amx->code, program + hdr->cod + tbl->offset, tbl->size);
  }

  return AMX_ERR_NONE;
}

int Pawn::LoadProgram() {
  (void) program_len;

  int result;
  AMX_HEADER hdr;
  memcpy(&hdr, program, sizeof(hdr));

  if (hdr.magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;

  memset(&amx, 0, sizeof(amx));
  amx.userdata[0] = this;

  header = malloc(hdr.cod);
  if (header == NULL)
    return AMX_ERR_MEMORY;

  memcpy(header, program, hdr.cod);

  if (hdr.flags & AMX_FLAG_OVERLAY) {
    datablock = malloc(hdr.stp - hdr.dat); // This block contains data, heap and stack
    if (datablock == NULL)
      return AMX_ERR_MEMORY;

    memcpy(datablock, program + hdr.dat, hdr.hea - hdr.dat);

    constexpr int overlaypool_overhead = 8;
    overlaypool = malloc(max_overlay_size + overlaypool_overhead);
    if (overlaypool == NULL)
      return AMX_ERR_MEMORY;

    amx_poolinit(&amx_pool, overlaypool, max_overlay_size + overlaypool_overhead);

    amx.data = (unsigned char*) datablock;
    amx.overlay = prun_Overlay;

    result = amx_Init(&amx, header);
    if (result != AMX_ERR_NONE) {
      free(header);
      header = NULL;
      free(datablock);
      datablock = NULL;
      free(overlaypool);
      overlaypool = NULL;
    }
  } else {
    datablock = malloc(hdr.stp); // This block contains code, data, heap and stack
    if (datablock == NULL)
      return AMX_ERR_MEMORY;

    memcpy(datablock, program, hdr.size);

    result = amx_Init(&amx, datablock);
    if (result != AMX_ERR_NONE) {
      free(header);
      header = NULL;
      free(datablock);
      datablock = NULL;
    }
  }

  return result;
}

extern "C" const AMX_NATIVE pawn_natives[] = {
  F_sprintf,
  F_lv_scr_act,
  F_lv_label_create,
  F_lv_btn_create,
  F_lv_obj_set_pos,
  F_lv_obj_set_size,
  F_lv_obj_set_event_cb,
  F_lv_obj_align,
  F_lv_obj_realign,
  F_lv_label_set_text,
  F_lv_obj_set_style_local_int,
  F_lv_obj_set_style_local_color,
  F_lv_obj_set_style_local_opa,
  F_lv_obj_set_style_local_ptr,
  F_get_datetime,
  F_get_datetime_short_str,
  F_status_icons_create,
  F_status_icons_update,
  F_raise_error,
};

Pawn::Pawn(AppControllers& controllers) : controllers(controllers) {
  int result = LoadProgram();
  if (result != AMX_ERR_NONE) {
    ShowError(result);
    return;
  }

  lv_obj_set_user_data(lv_scr_act(), &amx);

  cell* font;
  if (amx_FindPubVar(&amx, "font_jmec", &font) == AMX_ERR_NONE)
    *font = (cell) &jetbrains_mono_extrabold_compressed;

  result = amx_Exec(&amx, NULL, AMX_EXEC_MAIN);
  if (result != AMX_ERR_NONE) {
    ShowError(result);
    return;
  }

  if (amx_FindPublic(&amx, "@refresh", &refresh_index) == AMX_ERR_NONE) {
    taskRefresh = lv_task_create(RefreshTaskCallback, LV_DISP_DEF_REFR_PERIOD, LV_TASK_PRIO_MID, this);
    Refresh();
  }
  if (amx_FindPublic(&amx, "@touch", &touch_index) != AMX_ERR_NONE) {
    touch_index = -1;
  }
  if (amx_FindPublic(&amx, "@gesture", &gesture_index) != AMX_ERR_NONE) {
    gesture_index = -1;
  }
}

void Pawn::CleanUI() {
  if (taskRefresh) {
    lv_task_del(taskRefresh);
    taskRefresh = nullptr;
  }

  if (statusIcons) {
    delete statusIcons;
    statusIcons = nullptr;
  }

  lv_obj_clean(lv_scr_act());
}

Pawn::~Pawn() {
  CleanUI();

  amx_Cleanup(&amx);

  if (header)
    free(header);
  if (datablock)
    free(datablock);
  if (overlaypool)
    free(overlaypool);
}

void Pawn::Refresh() {
  int result = amx_Exec(&amx, NULL, refresh_index);
  if (result != AMX_ERR_NONE) {
    ShowError(result);
  }
}

void Pawn::ShowError(unsigned int amx_err) {
  static const char* amx_err_msgs[] = {
    nullptr,  "EXIT",   "ASSERT", "STACKERR", "BOUNDS",   "MEMACCESS", "INVINSTR", "STACKLOW", "HEAPLOW", "CALLBACK",
    "NATIVE", "DIVIDE", "SLEEP",  "INVSTATE", nullptr,    nullptr,     "MEMORY",   "FORMAT",   "VERSION", "NOTFOUND",
    "INDEX",  "DEBUG",  "INIT",   "USERDATA", "INIT_JIT", "PARAMS",    "DOMAIN",   "GENERAL",  "OVERLAY",
  };
  static const char* pawn_err_msgs[] = {
    "invalid parameter count", // PAWN_ERR_PARAMCOUNT
    "missing event handler",   // PAWN_ERR_MISSINGHANDLER
  };

  if (amx_err == AMX_ERR_EXIT) {
    running = false;
    return;
  }

  if (amx_err > 0 && amx_err < PAWN_ERR_FIRST && amx_err < sizeof(amx_err_msgs) / sizeof(*amx_err_msgs)) {
    ShowError(amx_err_msgs[amx_err]);
  } else if (amx_err >= PAWN_ERR_FIRST && amx_err - PAWN_ERR_FIRST < sizeof(pawn_err_msgs) / sizeof(*amx_err_msgs)) {
    ShowError(pawn_err_msgs[amx_err - PAWN_ERR_FIRST]);
  } else {
    char msg[25];
    snprintf(msg, sizeof(msg), "unknown error %d", amx_err);
    ShowError(msg);
  }
}

void Pawn::ShowError(const char* msg) {
  CleanUI();

  lv_obj_t* msglbl = lv_label_create(lv_scr_act(), nullptr);
  lv_obj_set_style_local_text_color(msglbl, LV_LABEL_PART_MAIN, LV_STATE_DEFAULT, lv_color_make(255, 0, 0));
  lv_label_set_long_mode(msglbl, LV_LABEL_LONG_BREAK);
  lv_label_set_text_fmt(msglbl, "Execution aborted:\n%s\n\nCIP: 0x%X", msg, amx.cip);
  lv_obj_set_width(msglbl, 240);
  lv_label_set_align(msglbl, LV_LABEL_ALIGN_CENTER);
  lv_obj_align(msglbl, NULL, LV_ALIGN_CENTER, 0, 0);
}

void Pawn::QueueError(unsigned int amx_err) {
  if (this->queued_error != 0)
    return;

  this->queued_error = amx_err;
  lv_async_call(
    [](void* user_data) {
      Pawn* pawn = static_cast<Pawn*>(user_data);
      pawn->ShowError(pawn->queued_error);
    },
    this);
}

bool Pawn::OnTouchEvent(TouchEvents event) {
  if (gesture_index < 0)
    return false;

  cell ret;

  amx_Push(&amx, (cell)event);

  int result = amx_Exec(&amx, &ret, gesture_index);
  if (result != AMX_ERR_NONE) {
    ShowError(result);
    return true;
  }

  return ret != 0;
}

bool Pawn::OnTouchEvent(uint16_t x, uint16_t y) {
  if (touch_index < 0)
    return false;

  cell ret;

  amx_Push(&amx, y);
  amx_Push(&amx, x);

  int result = amx_Exec(&amx, &ret, touch_index);
  if (result != AMX_ERR_NONE) {
    ShowError(result);
    return true;
  }

  return ret != 0;
}
