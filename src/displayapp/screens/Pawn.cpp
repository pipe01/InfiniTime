#include "Pawn.h"
#include <stdio.h>

using namespace Pinetime::Applications::Screens;

#define AMX_ERR_PARAMCOUNT 32

#define ASSERT_PARAMS(n)                                                                                                                   \
  if (params[0] != n * sizeof(cell)) {                                                                                                     \
    amx_RaiseError(amx, AMX_ERR_PARAMCOUNT);                                                                                               \
    return 0;                                                                                                                              \
  }

#define PARAMS_OBJ(i) ((lv_obj_t*) params[i])

static void event_handler(lv_obj_t* obj, lv_event_t event) {
  AMX* amx = (AMX*) lv_obj_get_user_data(lv_scr_act());
  int handler_index = (int) lv_obj_get_user_data(obj);

  amx_Push(amx, event);
  amx_Exec(amx, nullptr, handler_index);
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
    lv_label_set_text(label, "<invalid>");

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

static cell AMX_NATIVE_CALL F_sprintf(AMX* amx, const cell* params) {
  // param[0] is the number of total parameter bytes, divide it by cell size and subtract 3 to account for the fixed parameters
  int args_count = params[0] / sizeof(cell) - 3;

  cell* output = amx_Address(amx, params[1]);
  cell output_size = params[2] * sizeof(cell); // We assume the output array is packed, TODO: add a separate sprintf_unpacked function?

  char buf[output_size];

  char* fmt;
  amx_StrParam_Type(amx, params[3], fmt, char*);
  if (fmt == NULL)
    return 0;

  cell ret = 0;

#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  switch (args_count) {
    case 0:
      strcpy(buf, fmt);
      ret = strlen(fmt) + 1;
      break;
    case 1:
      ret = snprintf(buf, output_size, fmt, *amx_Address(amx, params[4]));
      break;
    case 2:
      ret = snprintf(buf, output_size, fmt, *amx_Address(amx, params[4]), *amx_Address(amx, params[5]));
      break;
    case 3:
      ret = snprintf(buf, output_size, fmt, *amx_Address(amx, params[4]), *amx_Address(amx, params[5]), *amx_Address(amx, params[6]));
      break;
    case 4:
      ret = snprintf(buf,
                     output_size,
                     fmt,
                     *amx_Address(amx, params[4]),
                     *amx_Address(amx, params[5]),
                     *amx_Address(amx, params[6]),
                     *amx_Address(amx, params[7]));
      break;
    case 5:
      ret = snprintf(buf,
                     output_size,
                     fmt,
                     *amx_Address(amx, params[4]),
                     *amx_Address(amx, params[5]),
                     *amx_Address(amx, params[6]),
                     *amx_Address(amx, params[7]),
                     *amx_Address(amx, params[8]));
      break;
    default:
      return 0;
  }
#pragma GCC diagnostic warning "-Wformat-nonliteral"

  amx_SetString(output, buf, 1, 0, output_size);

  return ret;
}


static int load_program(AMX* amx, const uint8_t* data) {
  AMX_HEADER hdr;
  memcpy(&hdr, data, sizeof(hdr));

  if (hdr.magic != AMX_MAGIC)
    return AMX_ERR_FORMAT;

  void* memblock = malloc(hdr.stp);
  if (memblock == NULL)
    return AMX_ERR_MEMORY;

  memcpy(memblock, data, hdr.size);

  memset(amx, 0, sizeof(*amx));

  int result = amx_Init(amx, memblock);
  if (result != AMX_ERR_NONE) {
    free(memblock);
    amx->base = NULL;
  }

  return result;
}

Pawn::Pawn(Controllers::DateTime& dateTimeController) : dateTimeController(dateTimeController) {
#include "program.h"

  load_program(&amx, program);
  (void) program_len;

  amx.userdata[0] = this;

  lv_obj_set_user_data(lv_scr_act(), &amx);

  cell* font;
  if (amx_FindPubVar(&amx, "font_jmec", &font) == AMX_ERR_NONE)
    *font = (cell) &jetbrains_mono_extrabold_compressed;

  const AMX_NATIVE_INFO natives[] = {
    {"sprintf", F_sprintf},
    {"lv_scr_act", F_lv_scr_act},
    {"lv_label_create", F_lv_label_create},
    {"lv_btn_create", F_lv_btn_create},
    {"lv_obj_set_pos", F_lv_obj_set_pos},
    {"lv_obj_set_size", F_lv_obj_set_size},
    {"lv_label_set_text", F_lv_label_set_text},
    {"lv_obj_set_event_cb", F_lv_obj_set_event_cb},
    {"lv_obj_set_style_local_int", F_lv_obj_set_style_local_int},
    {"lv_obj_set_style_local_color", F_lv_obj_set_style_local_color},
    {"lv_obj_set_style_local_opa", F_lv_obj_set_style_local_opa},
    {"lv_obj_set_style_local_ptr", F_lv_obj_set_style_local_ptr},
    {"lv_obj_align", F_lv_obj_align},
    {0, 0} /* terminator */
  };
  amx_Register(&amx, natives, -1);

  amx_Exec(&amx, NULL, AMX_EXEC_MAIN);

  if (amx_FindPublic(&amx, "@refresh", &refresh_index) == AMX_ERR_NONE) {
    taskRefresh = lv_task_create(RefreshTaskCallback, LV_DISP_DEF_REFR_PERIOD, LV_TASK_PRIO_MID, this);
    Refresh();
  }
}

Pawn::~Pawn() {
  if (taskRefresh)
    lv_task_del(taskRefresh);

  lv_obj_clean(lv_scr_act());

  amx_Cleanup(&amx);
  free(amx.base);
}

void Pawn::Refresh() {
  amx_Exec(&amx, NULL, refresh_index);
}
