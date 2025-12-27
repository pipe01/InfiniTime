#include "Pawn.h"
#include <stdio.h>

using namespace Pinetime::Applications::Screens;

#include "program.h"

static cell AMX_NATIVE_CALL F_lv_label_create(AMX*, const cell*) {
  lv_obj_t* label = lv_label_create(lv_scr_act(), nullptr);

  return (cell) label;
}

static cell AMX_NATIVE_CALL F_lv_obj_set_pos(AMX*, const cell* params) {
  lv_obj_t* label = (lv_obj_t*) params[1];
  lv_obj_set_pos(label, params[2], params[3]);

  return 0;
}

static cell AMX_NATIVE_CALL F_lv_label_set_text(AMX* amx, const cell* params) {
  lv_obj_t* label = (lv_obj_t*) params[1];

  char* text;
  amx_StrParam_Type(amx, params[2], text, char*);
  if (text != NULL)
    lv_label_set_text(label, text);
  else
    lv_label_set_text(label, "<invalid>");

  return 0;
}

static cell AMX_NATIVE_CALL F_sprintf(AMX* amx, const cell* params) {
  // param[0] is the number of total parameter bytes, divide it by cell size and subtract 3 to account for the fixed parameters
  int args_count = params[0] / sizeof(cell) - 3;

  cell *output = amx_Address(amx, params[1]);
  cell output_size = params[2];

  char buf[output_size];

  char *fmt;
  amx_StrParam_Type(amx, params[3], fmt, char*);
  if (fmt == NULL)
    return 0;

  cell ret = 0;

#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  switch (args_count)
  {
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
    ret = snprintf(buf, output_size, fmt, *amx_Address(amx, params[4]), *amx_Address(amx, params[5]), *amx_Address(amx, params[6]), *amx_Address(amx, params[7]));
    break;
  case 5:
    ret = snprintf(buf, output_size, fmt, *amx_Address(amx, params[4]), *amx_Address(amx, params[5]), *amx_Address(amx, params[6]), *amx_Address(amx, params[7]), *amx_Address(amx, params[8]));
    break;
  default:
    return 0;
  }
#pragma GCC diagnostic warning "-Wformat-nonliteral"

  amx_SetString(output, buf, 1, 0, output_size);

  return ret;
}

Pawn::Pawn() {
  uint8_t* prog = new uint8_t[program_len];
  memcpy(prog, program, program_len);

  memset(&amx, 0, sizeof(amx));
  amx_Init(&amx, prog);

  amx.userdata[0] = this;

  static AMX_NATIVE_INFO natives[] = {
    {"sprintf", F_sprintf},
    {"lv_label_create", F_lv_label_create},
    {"lv_obj_set_pos", F_lv_obj_set_pos},
    {"lv_label_set_text", F_lv_label_set_text},
    {0, 0} /* terminator */
  };
  amx_Register(&amx, natives, -1);

  amx_Exec(&amx, NULL, AMX_EXEC_MAIN);

  if (amx_FindPublic(&amx, "@refresh", &refresh_index) == AMX_ERR_NONE)
  {
    taskRefresh = lv_task_create(RefreshTaskCallback, LV_DISP_DEF_REFR_PERIOD, LV_TASK_PRIO_MID, this);
    Refresh();
  }
}

Pawn::~Pawn() {
  lv_task_del(taskRefresh);
  lv_obj_clean(lv_scr_act());

  amx_Cleanup(&amx);
  delete amx.base;
}

void Pawn::Refresh() {
  amx_Exec(&amx, NULL, refresh_index);
}
