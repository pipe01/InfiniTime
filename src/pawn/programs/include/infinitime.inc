#pragma library -

#include "lvgl"

#define DATETIME[.minute, .hour, .day, .year]

native sprintf(out[], size=sizeof out, const fmt[], const ...) = -1

#define jetbrains_mono_extrabold_compressed font_jmec // Name truncated because symbols have a max length of 31 characters
public stock const ptr:jetbrains_mono_extrabold_compressed

const touch_event: {
    TOUCH_None = 0,
    TOUCH_TAP,
    TOUCH_SWIPE_LEFT,
    TOUCH_SWIPE_RIGHT,
    TOUCH_SWIPE_UP,
    TOUCH_SWIPE_DOWN,
    TOUCH_LONG_TAP,
    TOUCH_DOUBLE_TAP,
}

native bool: read_datetime(out[DATETIME])                                = -15
native read_datetime_short_str(day_of_week{4} = 0, month_of_year{4} = 0) = -16

native status_icons_create() = -17
native status_icons_update() = -18
native bool: has_new_notifications() = -19

const setting: {
    SETTING_WATCHFACE = 0,
    SETTING_CHIME_OPTION,
    SETTING_PRIDE_FLAG,
    SETTING_CLOCK_TYPE,
    SETTING_WEATHER_FORMAT,
    SETTING_NOTIFICATION_STATUS,
    SETTING_STEPS_GOAL,
}
const {
    CLOCK_TYPE_H24 = 0,
    CLOCK_TYPE_H12
}
native get_setting(setting: s) = -20

const heartrate_state: {
    HEARTRATE_STOPPED = 0,
    HEARTRATE_NOT_ENOUGH_DATA
    HEARTRATE_NO_TOUCH
    HEARTRATE_RUNNING
}
native get_heartrate() = -21
native heartrate_state: get_heartrate_state() = -22

native get_step_number() = -23

native raise_error(err) = -24

forward @refresh()
forward @touch(x, y)
forward @gesture(touch_event: ev)

stock swap(&old_val, new_val) {
    var changed = old_val != new_val
    old_val = new_val
    return changed
}
