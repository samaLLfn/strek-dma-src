﻿// dear imgui, v1.89.6 WIP
// (widgets code)

/*

Index of this file:

// [SECTION] Forward Declarations
// [SECTION] Widgets: Text, etc.
// [SECTION] Widgets: Main (Button, Image, Checkbox, RadioButton, ProgressBar, Bullet, etc.)
// [SECTION] Widgets: Low-level Layout helpers (Spacing, Dummy, NewLine, Separator, etc.)
// [SECTION] Widgets: ComboBox
// [SECTION] Data Type and Data Formatting Helpers
// [SECTION] Widgets: DragScalar, DragFloat, DragInt, etc.
// [SECTION] Widgets: SliderScalar, SliderFloat, SliderInt, etc.
// [SECTION] Widgets: InputScalar, InputFloat, InputInt, etc.
// [SECTION] Widgets: InputText, InputTextMultiline
// [SECTION] Widgets: ColorEdit, ColorPicker, ColorButton, etc.
// [SECTION] Widgets: TreeNode, CollapsingHeader, etc.
// [SECTION] Widgets: Selectable
// [SECTION] Widgets: ListBox
// [SECTION] Widgets: PlotLines, PlotHistogram
// [SECTION] Widgets: Value helpers
// [SECTION] Widgets: MenuItem, BeginMenu, EndMenu, etc.
// [SECTION] Widgets: BeginTabBar, EndTabBar, etc.
// [SECTION] Widgets: BeginTabItem, EndTabItem, etc.
// [SECTION] Widgets: Columns, BeginColumns, EndColumns, etc.

*/

#if defined(_MSC_VER) && !defined(_CRT_SECURE_NO_WARNINGS)
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef SEGAUI_DEFINE_MATH_OPERATORS
#define SEGAUI_DEFINE_MATH_OPERATORS
#endif

#include "imgui.h"
#ifndef SEGAUI_DISABLE
#include "imgui_internal.h"

#include "imgui_settings.h"

// System includes
#if defined(_MSC_VER) && _MSC_VER <= 1500 // MSVC 2008 or earlier
#include <stddef.h>     // intptr_t
#else
#include <stdint.h>     // intptr_t
#endif
#include <map>
#include <string>
#include <d3d11.h>

//-------------------------------------------------------------------------
// Warnings
//-------------------------------------------------------------------------

// Visual Studio warnings
#ifdef _MSC_VER
#pragma warning (disable: 4127)     // condition expression is constant
#pragma warning (disable: 4996)     // 'This function or variable may be unsafe': strcpy, strdup, sprintf, vsnprintf, sscanf, fopen
#if defined(_MSC_VER) && _MSC_VER >= 1922 // MSVC 2019 16.2 or later
#pragma warning (disable: 5054)     // operator '|': deprecated between enumerations of different types
#endif
#pragma warning (disable: 26451)    // [Static Analyzer] Arithmetic overflow : Using operator 'xxx' on a 4 byte value and then casting the result to a 8 byte value. Cast the value to the wider type before calling operator 'xxx' to avoid overflow(io.2).
#pragma warning (disable: 26812)    // [Static Analyzer] The enum type 'xxx' is unscoped. Prefer 'enum class' over 'enum' (Enum.3).
#endif

// Clang/GCC warnings with -Weverything
#if defined(__clang__)
#if __has_warning("-Wunknown-warning-option")
#pragma clang diagnostic ignored "-Wunknown-warning-option"         // warning: unknown warning group 'xxx'                      // not all warnings are known by all Clang versions and they tend to be rename-happy.. so ignoring warnings triggers new warnings on some configuration. Great!
#endif
#pragma clang diagnostic ignored "-Wunknown-pragmas"                // warning: unknown warning group 'xxx'
#pragma clang diagnostic ignored "-Wold-style-cast"                 // warning: use of old-style cast                            // yes, they are more terse.
#pragma clang diagnostic ignored "-Wfloat-equal"                    // warning: comparing floating point with == or != is unsafe // storing and comparing against same constants (typically 0.0f) is ok.
#pragma clang diagnostic ignored "-Wformat-nonliteral"              // warning: format string is not a string literal            // passing non-literal to vsnformat(). yes, user passing incorrect format strings can crash the code.
#pragma clang diagnostic ignored "-Wsign-conversion"                // warning: implicit conversion changes signedness
#pragma clang diagnostic ignored "-Wzero-as-null-pointer-constant"  // warning: zero as null pointer constant                    // some standard header variations use #define NULL 0
#pragma clang diagnostic ignored "-Wdouble-promotion"               // warning: implicit conversion from 'float' to 'double' when passing argument to function  // using printf() is a misery with this as C++ va_arg ellipsis changes float to double.
#pragma clang diagnostic ignored "-Wenum-enum-conversion"           // warning: bitwise operation between different enumeration types ('XXXFlags_' and 'XXXFlagsPrivate_')
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"// warning: bitwise operation between different enumeration types ('XXXFlags_' and 'XXXFlagsPrivate_') is deprecated
#pragma clang diagnostic ignored "-Wimplicit-int-float-conversion"  // warning: implicit conversion from 'xxx' to 'float' may lose precision
#elif defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wpragmas"                          // warning: unknown option after '#pragma GCC diagnostic' kind
#pragma GCC diagnostic ignored "-Wformat-nonliteral"                // warning: format not a string literal, format string not checked
#pragma GCC diagnostic ignored "-Wclass-memaccess"                  // [__GNUC__ >= 8] warning: 'memset/memcpy' clearing/writing an object of type 'xxxx' with no trivial copy-assignment; use assignment or value-initialization instead
#pragma GCC diagnostic ignored "-Wdeprecated-enum-enum-conversion"  // warning: bitwise operation between different enumeration types ('XXXFlags_' and 'XXXFlagsPrivate_') is deprecated
#endif

//-------------------------------------------------------------------------
// Data
//-------------------------------------------------------------------------

// Widgets
static const float          DRAGDROP_HOLD_TO_OPEN_TIMER = 0.70f;    // Time for drag-hold to activate items accepting the SegaUiButtonFlags_PressedOnDragDropHold button behavior.
static const float          DRAG_MOUSE_THRESHOLD_FACTOR = 0.50f;    // Multiplier for the default value of io.MouseDragThreshold to make DragFloat/DragInt react faster to mouse drags.

// Those MIN/MAX values are not define because we need to point to them
static const signed char    IM_S8_MIN  = -128;
static const signed char    IM_S8_MAX  = 127;
static const unsigned char  IM_U8_MIN  = 0;
static const unsigned char  IM_U8_MAX  = 0xFF;
static const signed short   IM_S16_MIN = -32768;
static const signed short   IM_S16_MAX = 32767;
static const unsigned short IM_U16_MIN = 0;
static const unsigned short IM_U16_MAX = 0xFFFF;
static const ImS32          IM_S32_MIN = INT_MIN;    // (-2147483647 - 1), (0x80000000);
static const ImS32          IM_S32_MAX = INT_MAX;    // (2147483647), (0x7FFFFFFF)
static const ImU32          IM_U32_MIN = 0;
static const ImU32          IM_U32_MAX = UINT_MAX;   // (0xFFFFFFFF)
#ifdef LLONG_MIN
static const ImS64          IM_S64_MIN = LLONG_MIN;  // (-9223372036854775807ll - 1ll);
static const ImS64          IM_S64_MAX = LLONG_MAX;  // (9223372036854775807ll);
#else
static const ImS64          IM_S64_MIN = -9223372036854775807LL - 1;
static const ImS64          IM_S64_MAX = 9223372036854775807LL;
#endif
static const ImU64          IM_U64_MIN = 0;
#ifdef ULLONG_MAX
static const ImU64          IM_U64_MAX = ULLONG_MAX; // (0xFFFFFFFFFFFFFFFFull);
#else
static const ImU64          IM_U64_MAX = (2ULL * 9223372036854775807LL + 1);
#endif

//-------------------------------------------------------------------------
// [SECTION] Forward Declarations
//-------------------------------------------------------------------------

// For InputTextEx()
static bool             InputTextFilterCharacter(unsigned int* p_char, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* user_data, SegaUiInputSource input_source);
static int              InputTextCalcTextLenAndLineCount(const char* text_begin, const char** out_text_end);
static ImVec2           InputTextCalcTextSizeW(SegaUiContext* ctx, const ImWchar* text_begin, const ImWchar* text_end, const ImWchar** remaining = NULL, ImVec2* out_offset = NULL, bool stop_on_new_line = false);

//-------------------------------------------------------------------------
// [SECTION] Widgets: Text, etc.
//-------------------------------------------------------------------------
// - TextEx() [Internal]
// - TextUnformatted()
// - Text()
// - TextV()
// - TextColored()
// - TextColoredV()
// - TextDisabled()
// - TextDisabledV()
// - TextWrapped()
// - TextWrappedV()
// - LabelText()
// - LabelTextV()
// - BulletText()
// - BulletTextV()
//-------------------------------------------------------------------------

void invisible_shadow(const float alpha, const ImVec2 pos_min, const ImVec2 pos_max, ImU32 color, float shadow_tickness)
{
    SegaUi::PushStyleVar(SegaUiStyleVar_Alpha, alpha);
    SegaUi::PushClipRect(pos_min, pos_max, true);
    SegaUi::GetWindowDrawList()->AddShadowCircle(ImVec2(SegaUi::GetMousePos()), 1.f, SegaUi::GetColorU32(color), shadow_tickness, ImVec2(0, 0), 1000.f);
    SegaUi::PopClipRect();
    SegaUi::PopStyleVar();
}

const char* keys[] =
{
    "None",
    "Mouse 1",
    "Mouse 2",
    "CN",
    "Mouse 3",
    "Mouse 4",
    "Mouse 5",
    "-",
    "Back",
    "Tab",
    "-",
    "-",
    "CLR",
    "Enter",
    "-",
    "-",
    "Shift",
    "CTL",
    "Menu",
    "Pause",
    "Caps Lock",
    "KAN",
    "-",
    "JUN",
    "FIN",
    "KAN",
    "-",
    "Escape",
    "CON",
    "NCO",
    "ACC",
    "MAD",
    "Space",
    "PGU",
    "PGD",
    "End",
    "Home",
    "Left",
    "Up",
    "Right",
    "Down",
    "SEL",
    "PRI",
    "EXE",
    "PRI",
    "INS",
    "Delete",
    "HEL",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "WIN",
    "WIN",
    "APP",
    "-",
    "SLE",
    "Numpad 0",
    "Numpad 1",
    "Numpad 2",
    "Numpad 3",
    "Numpad 4",
    "Numpad 5",
    "Numpad 6",
    "Numpad 7",
    "Numpad 8",
    "Numpad 9",
    "MUL",
    "ADD",
    "SEP",
    "MIN",
    "Delete",
    "DIV",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "F8",
    "F9",
    "F10",
    "F11",
    "F12",
    "F13",
    "F14",
    "F15",
    "F16",
    "F17",
    "F18",
    "F19",
    "F20",
    "F21",
    "F22",
    "F23",
    "F24",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "NUM",
    "SCR",
    "EQU",
    "MAS",
    "TOY",
    "OYA",
    "OYA",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "-",
    "Shift",
    "Shift",
    "Ctrl",
    "Ctrl",
    "Alt",
    "Alt"
};

#include <string>

struct key_state
{
    ImVec4 background, text;
    ImVec2 size = ImVec2(0, 0);
    bool active = false;
    bool hovered = false;
    float alpha = 0.f, slow;
};

bool SegaUi::Keybind(const char* label, int* key, int* mode, bool label_active)
{
    SegaUiWindow* window = SegaUi::GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    SegaUiIO& io = g.IO;
    const SegaUiStyle& style = g.Style;

    const SegaUiID id = window->GetID(label);
    const float width = (GetContentRegionMax().x - style.WindowPadding.x);

    const ImRect rect(window->DC.CursorPos, window->DC.CursorPos + ImVec2(width, 22.f));

    ItemSize(ImRect(rect.Min, rect.Max - ImVec2(0, 5)));
    if (!SegaUi::ItemAdd(rect, id))
        return false;

    char buf_display[64] = "None";


    bool value_changed = false;
    int k = *key;

    std::string active_key = "";
    active_key += keys[*key];

    if (*key != 0 && g.ActiveId != id) {
        strcpy_s(buf_display, active_key.c_str());
    }
    else if (g.ActiveId == id) {
        strcpy_s(buf_display, "-");
    }

    const ImVec2 label_size = CalcTextSize(buf_display, NULL, true);

    ImRect clickable(ImVec2(rect.Max.x - 19 - label_size.x, rect.Min.y), rect.Max);
    bool hovered = ItemHoverable(clickable, id);

    static std::map<SegaUiID, key_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, key_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.background = ImLerp(it_anim->second.background, g.ActiveId == id ? c::keybind::background_active : c::keybind::background_inactive, g.IO.DeltaTime * 15.f);
    it_anim->second.text = ImLerp(it_anim->second.text, g.ActiveId == id ? c::text::text_active : hovered ? c::text::text_hov : c::text::text, SegaUi::GetIO().DeltaTime * 6.f);
    it_anim->second.slow = ImLerp(it_anim->second.slow, clickable.Min.x - rect.Min.x, g.IO.DeltaTime * 15.f);

    window->DrawList->AddRectFilled(ImVec2(it_anim->second.slow + rect.Min.x, clickable.Min.y), clickable.Max - ImVec2(0, 0), GetColorU32(it_anim->second.background), c::keybind::rounding);
    window->DrawList->AddRect(ImVec2(it_anim->second.slow + rect.Min.x, clickable.Min.y), clickable.Max - ImVec2(0, 0), GetColorU32(c::keybind::outline), c::keybind::rounding);

    if (label_active)  window->DrawList->AddText(rect.Min, GetColorU32(it_anim->second.text), label);

    SegaUi::PushClipRect(ImVec2(it_anim->second.slow + rect.Min.x, clickable.Min.y), clickable.Max, true);
    PushStyleColor(SegaUiCol_Text, c::text::text_active);
    RenderTextClipped(clickable.Min + ImVec2(0, 0), clickable.Max, buf_display, NULL, &label_size, ImVec2(0.5f, 0.5f));
    PopStyleColor();
    SegaUi::PopClipRect();

    if (hovered && io.MouseClicked[0])
    {
        if (g.ActiveId != id) {
            // Start edition
            memset(io.MouseDown, 0, sizeof(io.MouseDown));
            memset(io.KeysDown, 0, sizeof(io.KeysDown));
            *key = 0;
        }
        SegaUi::SetActiveID(id, window);
        SegaUi::FocusWindow(window);
    }
    else if (io.MouseClicked[0]) {
        // Release focus when we click outside
        if (g.ActiveId == id)
            SegaUi::ClearActiveID();
    }

    //if (g.ActiveId == id) {
    //    for (auto i = 0; i < 5; i++) {
    //        if (io.MouseDown[i]) {
    //            switch (i) {
    //            case 0:
    //                k = 0x01;
    //                break;
    //            case 1:
    //                k = 0x02;
    //                break;
    //            case 2:
    //                k = 0x04;
    //                break;
    //            case 3:
    //                k = 0x05;
    //                break;
    //            case 4:
    //                k = 0x06;
    //                break;
    //            }
    //            value_changed = true;
    //            SegaUi::ClearActiveID();
    //        }
    //    }
    //    if (!value_changed) {
    //        for (auto i = 0x08; i <= 0xA5; i++) {
    //            if (io.KeysDown[i]) {
    //                k = i;
    //                value_changed = true;
    //                SegaUi::ClearActiveID();
    //            }
    //        }
    //    }

    //    if (IsKeyPressedMap(SegaUiKey_Escape)) {
    //        *key = 0;
    //        SegaUi::ClearActiveID();
    //    }
    //    else {
    //        *key = k;
    //    }
    //}

    if (g.ActiveId == id) {



        for (auto i = 0; i < 5; i++) {
            if (io.MouseDown[i]) {
                switch (i) {
                case 0:
                    k = 0x01;
                    break;
                case 1:
                    k = 0x02;
                    break;
                case 2:
                    k = 0x04;
                    break;
                case 3:
                    k = 0x05;
                    break;
                case 4:
                    k = 0x06;
                    break;
                }
                value_changed = true;
                SegaUi::ClearActiveID();
            }
        }
        if (!value_changed) {

            for (int i = 0; i < 256; ++i) {
                //if (i != 93)
                    if (GetAsyncKeyState(i) & 0x8000) {
                        if (i == 0x01)
                        {
                            continue;
                        }
                        //MessageBoxA(0,("KEY: " + std::to_string(i)).c_str(), 0, 0);
                        k = i;
                        value_changed = true;
                        SegaUi::ClearActiveID();
                    }
            }
        }

        if (IsKeyPressedMap(SegaUiKey_Escape)) {
            *key = 0;
            SegaUi::ClearActiveID();
        }
        else {
            *key = k;
        }
    }

    if (hovered && g.IO.MouseClicked[1] || it_anim->second.active && (g.IO.MouseClicked[0] || g.IO.MouseClicked[1]) && !it_anim->second.hovered)
        it_anim->second.active = !it_anim->second.active;

    it_anim->second.alpha = ImClamp(it_anim->second.alpha + (8.f * g.IO.DeltaTime * (it_anim->second.active ? 1.f : -1.f)), 0.f, 1.f);

    PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(12, 12));
    PushStyleVar(SegaUiStyleVar_Alpha, it_anim->second.alpha);
    PushStyleVar(SegaUiStyleVar_WindowPadding, ImVec2(0, 5));
    PushStyleVar(SegaUiStyleVar_WindowRounding, c::combo::rounding);
    PushStyleColor(SegaUiCol_WindowBg, c::combo::background);
    PushStyleVar(SegaUiStyleVar_WindowBorderSize, 0.f);
    if (it_anim->second.alpha >= 0.01f)
    {
        SetNextWindowPos(ImVec2(clickable.GetCenter().x - (34 + 17 / 2), clickable.Max.y + 5));
        SetNextWindowSize(ImVec2(69 + 17, 87));

        Begin(label, NULL, SegaUiWindowFlags_NoDecoration | SegaUiWindowFlags_NoMove);
        {
            it_anim->second.hovered = IsWindowHovered();

            SegaUi::SetCursorPos(GetCursorPos() + ImVec2((86 - CalcTextSize("Hold").x) / 2, 0));
            if (Selectable("Hold", *mode == 0))
            {
                *mode = 0;
                it_anim->second.active = false;
            }

            SegaUi::SetCursorPos(GetCursorPos() + ImVec2((86 - CalcTextSize("Toggle").x) / 2, 0));
            if (Selectable("Toggle", *mode == 1))
            {
                *mode = 1;
                it_anim->second.active = false;
            }

            SegaUi::SetCursorPos(GetCursorPos() + ImVec2((86 - CalcTextSize("Always").x) / 2, 0));
            if (Selectable("Always", *mode == 2))
            {
                *mode = 2;
                it_anim->second.active = false;
            }
        }
        End();
    }
    PopStyleColor();
    PopStyleVar(5);

    return value_changed;
}


void SegaUi::TextEx(const char* text, const char* text_end, SegaUiTextFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;
    SegaUiContext& g = *GSegaUi;

    // Accept null ranges
    if (text == text_end)
        text = text_end = "";

    // Calculate length
    const char* text_begin = text;
    if (text_end == NULL)
        text_end = text + strlen(text); // FIXME-OPT

    const ImVec2 text_pos(window->DC.CursorPos.x, window->DC.CursorPos.y + window->DC.CurrLineTextBaseOffset);
    const float wrap_pos_x = window->DC.TextWrapPos;
    const bool wrap_enabled = (wrap_pos_x >= 0.0f);
    if (text_end - text <= 2000 || wrap_enabled)
    {
        // Common case
        const float wrap_width = wrap_enabled ? CalcWrapWidthForPos(window->DC.CursorPos, wrap_pos_x) : 0.0f;
        const ImVec2 text_size = CalcTextSize(text_begin, text_end, false, wrap_width);

        ImRect bb(text_pos, text_pos + text_size);
        ItemSize(text_size, 0.0f);
        if (!ItemAdd(bb, 0))
            return;

        // Render (we don't hide text after ## in this end-user function)
        RenderTextWrapped(bb.Min, text_begin, text_end, wrap_width);
    }
    else
    {
        // Long text!
        // Perform manual coarse clipping to optimize for long multi-line text
        // - From this point we will only compute the width of lines that are visible. Optimization only available when word-wrapping is disabled.
        // - We also don't vertically center the text within the line full height, which is unlikely to matter because we are likely the biggest and only item on the line.
        // - We use memchr(), pay attention that well optimized versions of those str/mem functions are much faster than a casually written loop.
        const char* line = text;
        const float line_height = GetTextLineHeight();
        ImVec2 text_size(0, 0);

        // Lines to skip (can't skip when logging text)
        ImVec2 pos = text_pos;
        if (!g.LogEnabled)
        {
            int lines_skippable = (int)((window->ClipRect.Min.y - text_pos.y) / line_height);
            if (lines_skippable > 0)
            {
                int lines_skipped = 0;
                while (line < text_end && lines_skipped < lines_skippable)
                {
                    const char* line_end = (const char*)memchr(line, '\n', text_end - line);
                    if (!line_end)
                        line_end = text_end;
                    if ((flags & SegaUiTextFlags_NoWidthForLargeClippedText) == 0)
                        text_size.x = ImMax(text_size.x, CalcTextSize(line, line_end).x);
                    line = line_end + 1;
                    lines_skipped++;
                }
                pos.y += lines_skipped * line_height;
            }
        }

        // Lines to render
        if (line < text_end)
        {
            ImRect line_rect(pos, pos + ImVec2(FLT_MAX, line_height));
            while (line < text_end)
            {
                if (IsClippedEx(line_rect, 0))
                    break;

                const char* line_end = (const char*)memchr(line, '\n', text_end - line);
                if (!line_end)
                    line_end = text_end;
                text_size.x = ImMax(text_size.x, CalcTextSize(line, line_end).x);
                RenderText(pos, line, line_end, false);
                line = line_end + 1;
                line_rect.Min.y += line_height;
                line_rect.Max.y += line_height;
                pos.y += line_height;
            }

            // Count remaining lines
            int lines_skipped = 0;
            while (line < text_end)
            {
                const char* line_end = (const char*)memchr(line, '\n', text_end - line);
                if (!line_end)
                    line_end = text_end;
                if ((flags & SegaUiTextFlags_NoWidthForLargeClippedText) == 0)
                    text_size.x = ImMax(text_size.x, CalcTextSize(line, line_end).x);
                line = line_end + 1;
                lines_skipped++;
            }
            pos.y += lines_skipped * line_height;
        }
        text_size.y = (pos - text_pos).y;

        ImRect bb(text_pos, text_pos + text_size);
        ItemSize(text_size, 0.0f);
        ItemAdd(bb, 0);
    }
}

void SegaUi::TextUnformatted(const char* text, const char* text_end)
{
    TextEx(text, text_end, SegaUiTextFlags_NoWidthForLargeClippedText);
}

void SegaUi::Text(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    TextV(fmt, args);
    va_end(args);
}

void SegaUi::TextV(const char* fmt, va_list args)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    const char* text, *text_end;
    ImFormatStringToTempBufferV(&text, &text_end, fmt, args);
    TextEx(text, text_end, SegaUiTextFlags_NoWidthForLargeClippedText);
}

void SegaUi::TextColored(const ImVec4& col, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    TextColoredV(col, fmt, args);
    va_end(args);
}

void SegaUi::TextColoredV(const ImVec4& col, const char* fmt, va_list args)
{
    PushStyleColor(SegaUiCol_Text, col);
    TextV(fmt, args);
    PopStyleColor();
}

void SegaUi::TextDisabled(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    TextDisabledV(fmt, args);
    va_end(args);
}

void SegaUi::TextDisabledV(const char* fmt, va_list args)
{
    SegaUiContext& g = *GSegaUi;
    PushStyleColor(SegaUiCol_Text, g.Style.Colors[SegaUiCol_TextDisabled]);
    TextV(fmt, args);
    PopStyleColor();
}

void SegaUi::TextWrapped(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    TextWrappedV(fmt, args);
    va_end(args);
}

void SegaUi::TextWrappedV(const char* fmt, va_list args)
{
    SegaUiContext& g = *GSegaUi;
    const bool need_backup = (g.CurrentWindow->DC.TextWrapPos < 0.0f);  // Keep existing wrap position if one is already set
    if (need_backup)
        PushTextWrapPos(0.0f);
    TextV(fmt, args);
    if (need_backup)
        PopTextWrapPos();
}

void SegaUi::LabelText(const char* label, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    LabelTextV(label, fmt, args);
    va_end(args);
}

// Add a label+text combo aligned to other label+value widgets
void SegaUi::LabelTextV(const char* label, const char* fmt, va_list args)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const float w = CalcItemWidth();

    const char* value_text_begin, *value_text_end;
    ImFormatStringToTempBufferV(&value_text_begin, &value_text_end, fmt, args);
    const ImVec2 value_size = CalcTextSize(value_text_begin, value_text_end, false);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    const ImVec2 pos = window->DC.CursorPos;
    const ImRect value_bb(pos, pos + ImVec2(w, value_size.y + style.FramePadding.y * 2));
    const ImRect total_bb(pos, pos + ImVec2(w + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f), ImMax(value_size.y, label_size.y) + style.FramePadding.y * 2));
    ItemSize(total_bb, style.FramePadding.y);
    if (!ItemAdd(total_bb, 0))
        return;

    // Render
    RenderTextClipped(value_bb.Min + style.FramePadding, value_bb.Max, value_text_begin, value_text_end, &value_size, ImVec2(0.0f, 0.0f));
    if (label_size.x > 0.0f)
        RenderText(ImVec2(value_bb.Max.x + style.ItemInnerSpacing.x, value_bb.Min.y + style.FramePadding.y), label);
}

void SegaUi::BulletText(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    BulletTextV(fmt, args);
    va_end(args);
}


void SegaUi::GlowText(ImFont* font, float size, const char* label, ImVec2 pos, ImU32 text_color)
{


    PushFont(font);
    for (int i = 0; i < c::text::glow_size; i++) {
        SegaUi::PushStyleVar(SegaUiStyleVar_Alpha, 1.f / i / 10);

        SegaUi::GetWindowDrawList()->AddText(font, size, pos + ImVec2(i, i), SegaUi::GetColorU32(text_color), label);

        SegaUi::PopStyleVar();
    }
    PopFont();
}

// Text with a little bullet aligned to the typical tree node.
void SegaUi::BulletTextV(const char* fmt, va_list args)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;

    const char* text_begin, *text_end;
    ImFormatStringToTempBufferV(&text_begin, &text_end, fmt, args);
    const ImVec2 label_size = CalcTextSize(text_begin, text_end, false);
    const ImVec2 total_size = ImVec2(g.FontSize + (label_size.x > 0.0f ? (label_size.x + style.FramePadding.x * 2) : 0.0f), label_size.y);  // Empty text doesn't add padding
    ImVec2 pos = window->DC.CursorPos;
    pos.y += window->DC.CurrLineTextBaseOffset;
    ItemSize(total_size, 0.0f);
    const ImRect bb(pos, pos + total_size);
    if (!ItemAdd(bb, 0))
        return;

    // Render
    ImU32 text_col = GetColorU32(SegaUiCol_Text);
    RenderBullet(window->DrawList, bb.Min + ImVec2(style.FramePadding.x + g.FontSize * 0.5f, g.FontSize * 0.5f), text_col);
    RenderText(bb.Min + ImVec2(g.FontSize + style.FramePadding.x * 2, 0.0f), text_begin, text_end, false);
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: Main
//-------------------------------------------------------------------------
// - ButtonBehavior() [Internal]
// - Button()
// - SmallButton()
// - InvisibleButton()
// - ArrowButton()
// - CloseButton() [Internal]
// - CollapseButton() [Internal]
// - GetWindowScrollbarID() [Internal]
// - GetWindowScrollbarRect() [Internal]
// - Scrollbar() [Internal]
// - () [Internal]
// - Image()
// - ImageButton()
// - Checkbox()
// - CheckboxFlagsT() [Internal]
// - CheckboxFlags()
// - RadioButton()
// - ProgressBar()
// - Bullet()
//-------------------------------------------------------------------------

// The ButtonBehavior() function is key to many interactions and used by many/most widgets.
// Because we handle so many cases (keyboard/gamepad navigation, drag and drop) and many specific behavior (via SegaUiButtonFlags_),
// this code is a little complex.
// By far the most common path is interacting with the Mouse using the default SegaUiButtonFlags_PressedOnClickRelease button behavior.
// See the series of events below and the corresponding state reported by dear imgui:
//------------------------------------------------------------------------------------------------------------------------------------------------
// with PressedOnClickRelease:             return-value  IsItemHovered()  IsItemActive()  IsItemActivated()  IsItemDeactivated()  IsItemClicked()
//   Frame N+0 (mouse is outside bb)        -             -                -               -                  -                    -
//   Frame N+1 (mouse moves inside bb)      -             true             -               -                  -                    -
//   Frame N+2 (mouse button is down)       -             true             true            true               -                    true
//   Frame N+3 (mouse button is down)       -             true             true            -                  -                    -
//   Frame N+4 (mouse moves outside bb)     -             -                true            -                  -                    -
//   Frame N+5 (mouse moves inside bb)      -             true             true            -                  -                    -
//   Frame N+6 (mouse button is released)   true          true             -               -                  true                 -
//   Frame N+7 (mouse button is released)   -             true             -               -                  -                    -
//   Frame N+8 (mouse moves outside bb)     -             -                -               -                  -                    -
//------------------------------------------------------------------------------------------------------------------------------------------------
// with PressedOnClick:                    return-value  IsItemHovered()  IsItemActive()  IsItemActivated()  IsItemDeactivated()  IsItemClicked()
//   Frame N+2 (mouse button is down)       true          true             true            true               -                    true
//   Frame N+3 (mouse button is down)       -             true             true            -                  -                    -
//   Frame N+6 (mouse button is released)   -             true             -               -                  true                 -
//   Frame N+7 (mouse button is released)   -             true             -               -                  -                    -
//------------------------------------------------------------------------------------------------------------------------------------------------
// with PressedOnRelease:                  return-value  IsItemHovered()  IsItemActive()  IsItemActivated()  IsItemDeactivated()  IsItemClicked()
//   Frame N+2 (mouse button is down)       -             true             -               -                  -                    true
//   Frame N+3 (mouse button is down)       -             true             -               -                  -                    -
//   Frame N+6 (mouse button is released)   true          true             -               -                  -                    -
//   Frame N+7 (mouse button is released)   -             true             -               -                  -                    -
//------------------------------------------------------------------------------------------------------------------------------------------------
// with PressedOnDoubleClick:              return-value  IsItemHovered()  IsItemActive()  IsItemActivated()  IsItemDeactivated()  IsItemClicked()
//   Frame N+0 (mouse button is down)       -             true             -               -                  -                    true
//   Frame N+1 (mouse button is down)       -             true             -               -                  -                    -
//   Frame N+2 (mouse button is released)   -             true             -               -                  -                    -
//   Frame N+3 (mouse button is released)   -             true             -               -                  -                    -
//   Frame N+4 (mouse button is down)       true          true             true            true               -                    true
//   Frame N+5 (mouse button is down)       -             true             true            -                  -                    -
//   Frame N+6 (mouse button is released)   -             true             -               -                  true                 -
//   Frame N+7 (mouse button is released)   -             true             -               -                  -                    -
//------------------------------------------------------------------------------------------------------------------------------------------------
// Note that some combinations are supported,
// - PressedOnDragDropHold can generally be associated with any flag.
// - PressedOnDoubleClick can be associated by PressedOnClickRelease/PressedOnRelease, in which case the second release event won't be reported.
//------------------------------------------------------------------------------------------------------------------------------------------------
// The behavior of the return-value changes when SegaUiButtonFlags_Repeat is set:
//                                         Repeat+                  Repeat+           Repeat+             Repeat+
//                                         PressedOnClickRelease    PressedOnClick    PressedOnRelease    PressedOnDoubleClick
//-------------------------------------------------------------------------------------------------------------------------------------------------
//   Frame N+0 (mouse button is down)       -                        true              -                   true
//   ...                                    -                        -                 -                   -
//   Frame N + RepeatDelay                  true                     true              -                   true
//   ...                                    -                        -                 -                   -
//   Frame N + RepeatDelay + RepeatRate*N   true                     true              -                   true
//-------------------------------------------------------------------------------------------------------------------------------------------------

bool SegaUi::ButtonBehavior(const ImRect& bb, SegaUiID id, bool* out_hovered, bool* out_held, SegaUiButtonFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();

    // Default only reacts to left mouse button
    if ((flags & SegaUiButtonFlags_MouseButtonMask_) == 0)
        flags |= SegaUiButtonFlags_MouseButtonDefault_;

    // Default behavior requires click + release inside bounding box
    if ((flags & SegaUiButtonFlags_PressedOnMask_) == 0)
        flags |= SegaUiButtonFlags_PressedOnDefault_;

    SegaUiWindow* backup_hovered_window = g.HoveredWindow;
    const bool flatten_hovered_children = (flags & SegaUiButtonFlags_FlattenChildren) && g.HoveredWindow && g.HoveredWindow->RootWindow == window;
    if (flatten_hovered_children)
        g.HoveredWindow = window;

#ifdef SEGAUI_ENABLE_TEST_ENGINE
    // Alternate registration spot, for when caller didn't use ItemAdd()
    if (id != 0 && g.LastItemData.ID != id)
        SEGAUI_TEST_ENGINE_ITEM_ADD(id, bb, NULL);
#endif

    bool pressed = false;
    bool hovered = ItemHoverable(bb, id);

    // Drag source doesn't report as hovered
    if (hovered && g.DragDropActive && g.DragDropPayload.SourceId == id && !(g.DragDropSourceFlags & SegaUiDragDropFlags_SourceNoDisableHover))
        hovered = false;

    // Special mode for Drag and Drop where holding button pressed for a long time while dragging another item triggers the button
    if (g.DragDropActive && (flags & SegaUiButtonFlags_PressedOnDragDropHold) && !(g.DragDropSourceFlags & SegaUiDragDropFlags_SourceNoHoldToOpenOthers))
        if (IsItemHovered(SegaUiHoveredFlags_AllowWhenBlockedByActiveItem))
        {
            hovered = true;
            SetHoveredID(id);
            if (g.HoveredIdTimer - g.IO.DeltaTime <= DRAGDROP_HOLD_TO_OPEN_TIMER && g.HoveredIdTimer >= DRAGDROP_HOLD_TO_OPEN_TIMER)
            {
                pressed = true;
                g.DragDropHoldJustPressedId = id;
                FocusWindow(window);
            }
        }

    if (flatten_hovered_children)
        g.HoveredWindow = backup_hovered_window;

    // AllowOverlap mode (rarely used) requires previous frame HoveredId to be null or to match. This allows using patterns where a later submitted widget overlaps a previous one.
    if (hovered && (flags & SegaUiButtonFlags_AllowItemOverlap) && (g.HoveredIdPreviousFrame != id && g.HoveredIdPreviousFrame != 0))
        hovered = false;

    // Mouse handling
    const SegaUiID test_owner_id = (flags & SegaUiButtonFlags_NoTestKeyOwner) ? SegaUiKeyOwner_Any : id;
    if (hovered)
    {
        // Poll mouse buttons
        // - 'mouse_button_clicked' is generally carried into ActiveIdMouseButton when setting ActiveId.
        // - Technically we only need some values in one code path, but since this is gated by hovered test this is fine.
        int mouse_button_clicked = -1;
        int mouse_button_released = -1;
        for (int button = 0; button < 3; button++)
            if (flags & (SegaUiButtonFlags_MouseButtonLeft << button)) // Handle SegaUiButtonFlags_MouseButtonRight and SegaUiButtonFlags_MouseButtonMiddle here.
            {
                if (IsMouseClicked(button, test_owner_id) && mouse_button_clicked == -1) { mouse_button_clicked = button; }
                if (IsMouseReleased(button, test_owner_id) && mouse_button_released == -1) { mouse_button_released = button; }
            }

        // Process initial action
        if (!(flags & SegaUiButtonFlags_NoKeyModifiers) || (!g.IO.KeyCtrl && !g.IO.KeyShift && !g.IO.KeyAlt))
        {
            if (mouse_button_clicked != -1 && g.ActiveId != id)
            {
                if (!(flags & SegaUiButtonFlags_NoSetKeyOwner))
                    SetKeyOwner(MouseButtonToKey(mouse_button_clicked), id);
                if (flags & (SegaUiButtonFlags_PressedOnClickRelease | SegaUiButtonFlags_PressedOnClickReleaseAnywhere))
                {
                    SetActiveID(id, window);
                    g.ActiveIdMouseButton = mouse_button_clicked;
                    if (!(flags & SegaUiButtonFlags_NoNavFocus))
                        SetFocusID(id, window);
                    FocusWindow(window);
                }
                if ((flags & SegaUiButtonFlags_PressedOnClick) || ((flags & SegaUiButtonFlags_PressedOnDoubleClick) && g.IO.MouseClickedCount[mouse_button_clicked] == 2))
                {
                    pressed = true;
                    if (flags & SegaUiButtonFlags_NoHoldingActiveId)
                        ClearActiveID();
                    else
                        SetActiveID(id, window); // Hold on ID
                    if (!(flags & SegaUiButtonFlags_NoNavFocus))
                        SetFocusID(id, window);
                    g.ActiveIdMouseButton = mouse_button_clicked;
                    FocusWindow(window);
                }
            }
            if (flags & SegaUiButtonFlags_PressedOnRelease)
            {
                if (mouse_button_released != -1)
                {
                    const bool has_repeated_at_least_once = (flags & SegaUiButtonFlags_Repeat) && g.IO.MouseDownDurationPrev[mouse_button_released] >= g.IO.KeyRepeatDelay; // Repeat mode trumps on release behavior
                    if (!has_repeated_at_least_once)
                        pressed = true;
                    if (!(flags & SegaUiButtonFlags_NoNavFocus))
                        SetFocusID(id, window);
                    ClearActiveID();
                }
            }

            // 'Repeat' mode acts when held regardless of _PressedOn flags (see table above).
            // Relies on repeat logic of IsMouseClicked() but we may as well do it ourselves if we end up exposing finer RepeatDelay/RepeatRate settings.
            if (g.ActiveId == id && (flags & SegaUiButtonFlags_Repeat))
                if (g.IO.MouseDownDuration[g.ActiveIdMouseButton] > 0.0f && IsMouseClicked(g.ActiveIdMouseButton, test_owner_id, SegaUiInputFlags_Repeat))
                    pressed = true;
        }

        if (pressed)
            g.NavDisableHighlight = true;
    }

    // Gamepad/Keyboard navigation
    // We report navigated item as hovered but we don't set g.HoveredId to not interfere with mouse.
    if (g.NavId == id && !g.NavDisableHighlight && g.NavDisableMouseHover && (g.ActiveId == 0 || g.ActiveId == id || g.ActiveId == window->MoveId))
        if (!(flags & SegaUiButtonFlags_NoHoveredOnFocus))
            hovered = true;
    if (g.NavActivateDownId == id)
    {
        bool nav_activated_by_code = (g.NavActivateId == id);
        bool nav_activated_by_inputs = (g.NavActivatePressedId == id);
        if (!nav_activated_by_inputs && (flags & SegaUiButtonFlags_Repeat))
        {
            // Avoid pressing multiple keys from triggering excessive amount of repeat events
            const SegaUiKeyData* key1 = GetKeyData(SegaUiKey_Space);
            const SegaUiKeyData* key2 = GetKeyData(SegaUiKey_Enter);
            const SegaUiKeyData* key3 = GetKeyData(SegaUiKey_NavGamepadActivate);
            const float t1 = ImMax(ImMax(key1->DownDuration, key2->DownDuration), key3->DownDuration);
            nav_activated_by_inputs = CalcTypematicRepeatAmount(t1 - g.IO.DeltaTime, t1, g.IO.KeyRepeatDelay, g.IO.KeyRepeatRate) > 0;
        }
        if (nav_activated_by_code || nav_activated_by_inputs)
        {
            // Set active id so it can be queried by user via IsItemActive(), equivalent of holding the mouse button.
            pressed = true;
            SetActiveID(id, window);
            g.ActiveIdSource = g.NavInputSource;
            if (!(flags & SegaUiButtonFlags_NoNavFocus))
                SetFocusID(id, window);
        }
    }

    // Process while held
    bool held = false;
    if (g.ActiveId == id)
    {
        if (g.ActiveIdSource == SegaUiInputSource_Mouse)
        {
            if (g.ActiveIdIsJustActivated)
                g.ActiveIdClickOffset = g.IO.MousePos - bb.Min;

            const int mouse_button = g.ActiveIdMouseButton;
            if (mouse_button == -1)
            {
                // Fallback for the rare situation were g.ActiveId was set programmatically or from another widget (e.g. #6304).
                ClearActiveID();
            }
            else if (IsMouseDown(mouse_button, test_owner_id))
            {
                held = true;
            }
            else
            {
                bool release_in = hovered && (flags & SegaUiButtonFlags_PressedOnClickRelease) != 0;
                bool release_anywhere = (flags & SegaUiButtonFlags_PressedOnClickReleaseAnywhere) != 0;
                if ((release_in || release_anywhere) && !g.DragDropActive)
                {
                    // Report as pressed when releasing the mouse (this is the most common path)
                    bool is_double_click_release = (flags & SegaUiButtonFlags_PressedOnDoubleClick) && g.IO.MouseReleased[mouse_button] && g.IO.MouseClickedLastCount[mouse_button] == 2;
                    bool is_repeating_already = (flags & SegaUiButtonFlags_Repeat) && g.IO.MouseDownDurationPrev[mouse_button] >= g.IO.KeyRepeatDelay; // Repeat mode trumps <on release>
                    bool is_button_avail_or_owned = TestKeyOwner(MouseButtonToKey(mouse_button), test_owner_id);
                    if (!is_double_click_release && !is_repeating_already && is_button_avail_or_owned)
                        pressed = true;
                }
                ClearActiveID();
            }
            if (!(flags & SegaUiButtonFlags_NoNavFocus))
                g.NavDisableHighlight = true;
        }
        else if (g.ActiveIdSource == SegaUiInputSource_Keyboard || g.ActiveIdSource == SegaUiInputSource_Gamepad)
        {
            // When activated using Nav, we hold on the ActiveID until activation button is released
            if (g.NavActivateDownId != id)
                ClearActiveID();
        }
        if (pressed)
            g.ActiveIdHasBeenPressedBefore = true;
    }

    if (out_hovered) *out_hovered = hovered;
    if (out_held) *out_held = held;

    return pressed;
}

struct tab_state
{
    ImVec4 image, text;
    float background_opticaly = 0.f;
};
namespace font
{
    extern ImFont* inter_bold;
    extern ImFont* inter_default;
}


bool SegaUi::Tabs(bool selected, ImTextureID image, const char* label, const ImVec2& size_arg, SegaUiButtonFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();

    if (window->SkipItems) return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    ImVec2 pos = window->DC.CursorPos;

    ImVec2 size = CalcItemSize(size_arg, label_size.x, label_size.y);

    const ImRect bb(pos, pos + size);
    //const ImRect image_bb(pos + ImVec2(5, (size_arg.y - 21) / 2), pos + ImVec2(26, (size_arg.y + 21) / 2));
    const ImRect image_bb(pos + ImVec2(5, (size_arg.y - 25) / 2), pos + ImVec2(30, (size_arg.y + 25) / 2));

    ItemSize(size, 0.f);

    if (!ItemAdd(bb, id)) return false;

    bool hovered, held, pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

    static std::map<SegaUiID, tab_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, tab_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.background_opticaly = ImLerp(it_anim->second.background_opticaly, selected ? 1.f : 0.f, g.IO.DeltaTime * 6.f);

    it_anim->second.image = ImLerp(it_anim->second.image, selected ? c::accent : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);
    it_anim->second.text = ImLerp(it_anim->second.text, selected ? c::text::text_active : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);

    PushStyleVar(SegaUiStyleVar_Alpha, it_anim->second.background_opticaly);

    GetWindowDrawList()->AddRectFilled(bb.Min, bb.Max, GetColorU32(c::tabs::background), c::tabs::rounding);
    GetWindowDrawList()->AddRect(bb.Min, bb.Max, GetColorU32(c::tabs::outline), c::tabs::rounding);

    GetWindowDrawList()->AddRectFilled(bb.Min + ImVec2(size_arg.x - 4, 6), bb.Max - ImVec2(0, 6), GetColorU32(c::accent), 30.f, ImDrawCornerFlags_Left);
    PopStyleVar();

    GetWindowDrawList()->AddImage(image, image_bb.Min, image_bb.Max, ImVec2(0, 0), ImVec2(1, 1), GetColorU32(it_anim->second.image));

    GlowText(font::inter_bold, 17.f, label, bb.Min + ImVec2(34, (size_arg.y - CalcTextSize(label).y) / 2), GetColorU32(it_anim->second.text));
    if (pressed)
    {
        PlaySound(TEXT("C:/ProgramData/MinecraftClickButtonSound.wav"), NULL, SND_FILENAME | SND_ASYNC);
    }

    return pressed;
}

struct subtab_state
{
    ImVec4 shadow, line, text;
    float text_offset, background_opticaly;
};


bool SegaUi::SubTab(bool selectable, const char* label, const ImVec2& size_arg)
{
    SegaUiWindow* window = GetCurrentWindow();

    if (window->SkipItems) return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true), pos = window->DC.CursorPos;

    ImVec2 size = CalcItemSize(size_arg, label_size.x, label_size.y);

    const ImRect bb(pos, pos + size);

    ItemSize(size, 0.f);
    if (!ItemAdd(bb, id)) return false;

    bool hovered, held, pressed = ButtonBehavior(bb, id, &hovered, &held, 0);

    static std::map<SegaUiID, subtab_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, subtab_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.background_opticaly = ImLerp(it_anim->second.background_opticaly, selectable ? 1.f : 0.f, g.IO.DeltaTime * 6.f);

    it_anim->second.text = ImLerp(it_anim->second.text, selectable ? c::accent : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);

    it_anim->second.text_offset = ImClamp(it_anim->second.text_offset + (6.f * g.IO.DeltaTime * (selectable ? 10.f : -5.f)), 0.f, 6.f);

    PushStyleVar(SegaUiStyleVar_Alpha, it_anim->second.background_opticaly);
    SegaUi::GetWindowDrawList()->AddRectFilled(bb.Min + ImVec2(size_arg.x / 3, size_arg.y - 4), bb.Max - ImVec2(size_arg.x / 3, 0), GetColorU32(c::accent), 30.f, ImDrawCornerFlags_Top);
 //   SegaUi::GetWindowDrawList()->AddShadowRect(bb.Min + ImVec2(0, size_arg.y - 1), bb.Max, 25.f, ImVec2(0, -2), GetColorU32(c::accent), 0.f);

    PopStyleVar();

  //  PushStyleColor(SegaUiCol_Text, GetColorU32(it_anim->second.text));
  //  RenderTextClipped(bb.Min, bb.Max - ImVec2(0, it_anim->second.text_offset), label, NULL, &label_size, ImVec2(0.5, 0.5), &bb);

    GlowText(font::inter_bold, 17.f, label, bb.Min + ImVec2((size_arg.x - CalcTextSize(label).x) / 2, (size_arg.y - CalcTextSize(label).y) / 2), GetColorU32(it_anim->second.text));


  //  PopStyleColor();
    if (pressed)
    {
        PlaySound(TEXT("C:/ProgramData/MinecraftClickButtonSound.wav"), NULL, SND_FILENAME | SND_ASYNC);
    }
    return pressed;
}

struct button_state
{
    ImVec4 background, text, outline;
    float circle_size, delay_opticaly;
};

bool SegaUi::ButtonEx(const char* label, const ImVec2& size_arg, SegaUiButtonFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();

    if (window->SkipItems) return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true), pos = window->DC.CursorPos;
    static bool circle_active = false;
    ImVec2 size = CalcItemSize(size_arg, label_size.x, label_size.y);

    POINT cord;
    GetCursorPos(&cord);

    const ImRect bb(pos, pos + size);

    ItemSize(size, 0.f);
    if (!ItemAdd(bb, id)) return false;

    bool hovered, held, pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

    static std::map<SegaUiID, button_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, button_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.background = ImLerp(it_anim->second.background, IsItemActive() ? c::button::background_active : c::button::background_inactive, g.IO.DeltaTime * 6.f);
    it_anim->second.outline = ImLerp(it_anim->second.outline, IsItemActive() ? c::accent : c::button::outline, g.IO.DeltaTime * 6.f);

    if (IsItemClicked()) circle_active = true;

    it_anim->second.circle_size = ImLerp(it_anim->second.circle_size, circle_active ? 251.f : 0.f, g.IO.DeltaTime * 15.f);
    it_anim->second.delay_opticaly = ImLerp(it_anim->second.delay_opticaly, circle_active ? 1.f : 0.f, g.IO.DeltaTime * 1.f);


    if (it_anim->second.circle_size > 250) circle_active = false;

    SegaUi::GetWindowDrawList()->AddRectFilled(bb.Min, bb.Max, GetColorU32(it_anim->second.outline), c::button::rounding);

    invisible_shadow(1.f, bb.Min, bb.Max, GetColorU32(c::accent), 500);

    SegaUi::GetWindowDrawList()->AddRectFilled(bb.Min + ImVec2(1, 1), bb.Max - ImVec2(1, 1), GetColorU32(it_anim->second.background), c::button::rounding);

    PushStyleVar(SegaUiStyleVar_Alpha, it_anim->second.delay_opticaly);
    PushClipRect(bb.Min, bb.Max, true);
    GetWindowDrawList()->AddShadowCircle(bb.Min + ImVec2(size_arg) / 2, 3 + it_anim->second.circle_size, GetColorU32(c::accent), 3 + it_anim->second.circle_size, ImVec2(0, 0), 100);
    PopClipRect();
    PopStyleVar();

    SegaUi::GetWindowDrawList()->AddText(ImVec2(bb.Min.x + (size_arg.x - CalcTextSize(label).x) / 2, bb.Max.y - CalcTextSize(label).y - (size.y - CalcTextSize(label).y) / 2), GetColorU32(c::text::text_active), label);

    return pressed;
}

bool SegaUi::Button(const char* label, const ImVec2& size_arg)
{
    return ButtonEx(label, size_arg, SegaUiButtonFlags_None);
}

// Small buttons fits within text without additional vertical spacing.
bool SegaUi::SmallButton(const char* label)
{
    SegaUiContext& g = *GSegaUi;
    float backup_padding_y = g.Style.FramePadding.y;
    g.Style.FramePadding.y = 0.0f;
    bool pressed = ButtonEx(label, ImVec2(0, 0), SegaUiButtonFlags_AlignTextBaseLine);
    g.Style.FramePadding.y = backup_padding_y;
    return pressed;
}

// Tip: use SegaUi::PushID()/PopID() to push indices or pointers in the ID stack.
// Then you can keep 'str_id' empty or the same for all your buttons (instead of creating a string based on a non-string id)
bool SegaUi::InvisibleButton(const char* str_id, const ImVec2& size_arg, SegaUiButtonFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    // Cannot use zero-size for InvisibleButton(). Unlike Button() there is not way to fallback using the label size.
    IM_ASSERT(size_arg.x != 0.0f && size_arg.y != 0.0f);

    const SegaUiID id = window->GetID(str_id);
    ImVec2 size = CalcItemSize(size_arg, 0.0f, 0.0f);
    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size);
    ItemSize(size);
    if (!ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, str_id, g.LastItemData.StatusFlags);
    return pressed;
}

bool SegaUi::ArrowButtonEx(const char* str_id, SegaUiDir dir, ImVec2 size, SegaUiButtonFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const SegaUiID id = window->GetID(str_id);
    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size);
    const float default_size = GetFrameHeight();
    ItemSize(size, (size.y >= default_size) ? g.Style.FramePadding.y : -1.0f);
    if (!ItemAdd(bb, id))
        return false;

    if (g.LastItemData.InFlags & SegaUiItemFlags_ButtonRepeat)
        flags |= SegaUiButtonFlags_Repeat;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

    // Render
    const ImU32 bg_col = GetColorU32((held && hovered) ? SegaUiCol_ButtonActive : hovered ? SegaUiCol_ButtonHovered : SegaUiCol_Button);
    const ImU32 text_col = GetColorU32(SegaUiCol_Text);
    RenderNavHighlight(bb, id);
    RenderFrame(bb.Min, bb.Max, bg_col, true, g.Style.FrameRounding);
    RenderArrow(window->DrawList, bb.Min + ImVec2(ImMax(0.0f, (size.x - g.FontSize) * 0.5f), ImMax(0.0f, (size.y - g.FontSize) * 0.5f)), text_col, dir);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, str_id, g.LastItemData.StatusFlags);
    return pressed;
}

bool SegaUi::ArrowButton(const char* str_id, SegaUiDir dir)
{
    float sz = GetFrameHeight();
    return ArrowButtonEx(str_id, dir, ImVec2(sz, sz), SegaUiButtonFlags_None);
}

// Button to close a window
bool SegaUi::CloseButton(SegaUiID id, const ImVec2& pos)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;

    // Tweak 1: Shrink hit-testing area if button covers an abnormally large proportion of the visible region. That's in order to facilitate moving the window away. (#3825)
    // This may better be applied as a general hit-rect reduction mechanism for all widgets to ensure the area to move window is always accessible?
    const ImRect bb(pos, pos + ImVec2(g.FontSize, g.FontSize) + g.Style.FramePadding * 2.0f);
    ImRect bb_interact = bb;
    const float area_to_visible_ratio = window->OuterRectClipped.GetArea() / bb.GetArea();
    if (area_to_visible_ratio < 1.5f)
        bb_interact.Expand(ImFloor(bb_interact.GetSize() * -0.25f));

    // Tweak 2: We intentionally allow interaction when clipped so that a mechanical Alt,Right,Activate sequence can always close a window.
    // (this isn't the regular behavior of buttons, but it doesn't affect the user much because navigation tends to keep items visible).
    bool is_clipped = !ItemAdd(bb_interact, id);

    bool hovered, held;
    bool pressed = ButtonBehavior(bb_interact, id, &hovered, &held);
    if (is_clipped)
        return pressed;

    // Render
    // FIXME: Clarify this mess
    ImU32 col = GetColorU32(held ? SegaUiCol_ButtonActive : SegaUiCol_ButtonHovered);
    ImVec2 center = bb.GetCenter();
    if (hovered)
        window->DrawList->AddCircleFilled(center, ImMax(2.0f, g.FontSize * 0.5f + 1.0f), col);

    float cross_extent = g.FontSize * 0.5f * 0.7071f - 1.0f;
    ImU32 cross_col = GetColorU32(SegaUiCol_Text);
    center -= ImVec2(0.5f, 0.5f);
    window->DrawList->AddLine(center + ImVec2(+cross_extent, +cross_extent), center + ImVec2(-cross_extent, -cross_extent), cross_col, 1.0f);
    window->DrawList->AddLine(center + ImVec2(+cross_extent, -cross_extent), center + ImVec2(-cross_extent, +cross_extent), cross_col, 1.0f);

    return pressed;
}

bool SegaUi::CollapseButton(SegaUiID id, const ImVec2& pos)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;

    ImRect bb(pos, pos + ImVec2(g.FontSize, g.FontSize) + g.Style.FramePadding * 2.0f);
    ItemAdd(bb, id);
    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, SegaUiButtonFlags_None);

    // Render
    ImU32 bg_col = GetColorU32((held && hovered) ? SegaUiCol_ButtonActive : hovered ? SegaUiCol_ButtonHovered : SegaUiCol_Button);
    ImU32 text_col = GetColorU32(SegaUiCol_Text);
    if (hovered || held)
        window->DrawList->AddCircleFilled(bb.GetCenter()/*+ ImVec2(0.0f, -0.5f)*/, g.FontSize * 0.5f + 1.0f, bg_col);
    RenderArrow(window->DrawList, bb.Min + g.Style.FramePadding, text_col, window->Collapsed ? SegaUiDir_Right : SegaUiDir_Down, 1.0f);

    // Switch to moving the window after mouse is moved beyond the initial drag threshold
    if (IsItemActive() && IsMouseDragging(0))
        StartMouseMovingWindow(window);

    return pressed;
}

SegaUiID SegaUi::GetWindowScrollbarID(SegaUiWindow* window, SegaUiAxis axis)
{
    return window->GetID(axis == SegaUiAxis_X ? "#SCROLLX" : "#SCROLLY");
}

// Return scrollbar rectangle, must only be called for corresponding axis if window->ScrollbarX/Y is set.
ImRect SegaUi::GetWindowScrollbarRect(SegaUiWindow* window, SegaUiAxis axis)
{
    const ImRect outer_rect = window->Rect();
    const ImRect inner_rect = window->InnerRect;
    const float border_size = window->WindowBorderSize;
    const float scrollbar_size = window->ScrollbarSizes[axis ^ 1]; // (ScrollbarSizes.x = width of Y scrollbar; ScrollbarSizes.y = height of X scrollbar)
    IM_ASSERT(scrollbar_size > 0.0f);
    if (axis == SegaUiAxis_X)
        return ImRect(inner_rect.Min.x, ImMax(outer_rect.Min.y, outer_rect.Max.y - border_size - scrollbar_size), inner_rect.Max.x, outer_rect.Max.y);
    else
        return ImRect(ImMax(outer_rect.Min.x, outer_rect.Max.x - border_size - scrollbar_size), inner_rect.Min.y, outer_rect.Max.x, inner_rect.Max.y);
}

void SegaUi::Scrollbar(SegaUiAxis axis)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    const SegaUiID id = GetWindowScrollbarID(window, axis);

    // Calculate scrollbar bounding box
    ImRect bb = GetWindowScrollbarRect(window, axis);
    ImDrawFlags rounding_corners = ImDrawFlags_RoundCornersNone;
    if (axis == SegaUiAxis_X)
    {
        rounding_corners |= ImDrawFlags_RoundCornersBottomLeft;
        if (!window->ScrollbarY)
            rounding_corners |= ImDrawFlags_RoundCornersBottomRight;
    }
    else
    {
        if ((window->Flags & SegaUiWindowFlags_NoTitleBar) && !(window->Flags & SegaUiWindowFlags_MenuBar))
            rounding_corners |= ImDrawFlags_RoundCornersTopRight;
        if (!window->ScrollbarX)
            rounding_corners |= ImDrawFlags_RoundCornersBottomRight;
    }
    float size_avail = window->InnerRect.Max[axis] - window->InnerRect.Min[axis];
    float size_contents = window->ContentSize[axis] + window->WindowPadding[axis] * 2.0f;
    ImS64 scroll = (ImS64)window->Scroll[axis];
    ScrollbarEx(bb, id, axis, &scroll, (ImS64)size_avail, (ImS64)size_contents, rounding_corners);
    window->Scroll[axis] = (float)scroll;
}

// Vertical/Horizontal scrollbar
// The entire piece of code below is rather confusing because:
// - We handle absolute seeking (when first clicking outside the grab) and relative manipulation (afterward or when clicking inside the grab)
// - We store values as normalized ratio and in a form that allows the window content to change while we are holding on a scrollbar
// - We handle both horizontal and vertical scrollbars, which makes the terminology not ideal.
// Still, the code should probably be made simpler..
bool SegaUi::ScrollbarEx(const ImRect& bb_frame, SegaUiID id, SegaUiAxis axis, ImS64* p_scroll_v, ImS64 size_avail_v, ImS64 size_contents_v, ImDrawFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    const float bb_frame_width = bb_frame.GetWidth();
    const float bb_frame_height = bb_frame.GetHeight();
    if (bb_frame_width <= 0.0f || bb_frame_height <= 0.0f)
        return false;

    // When we are too small, start hiding and disabling the grab (this reduce visual noise on very small window and facilitate using the window resize grab)
    float alpha = 1.0f;
    if ((axis == SegaUiAxis_Y) && bb_frame_height < g.FontSize + g.Style.FramePadding.y * 2.0f)
        alpha = ImSaturate((bb_frame_height - g.FontSize) / (g.Style.FramePadding.y * 2.0f));
    if (alpha <= 0.0f)
        return false;

    const SegaUiStyle& style = g.Style;
    const bool allow_interaction = (alpha >= 1.0f);

    ImRect bb = bb_frame;
    bb.Expand(ImVec2(-ImClamp(IM_FLOOR((bb_frame_width - 2.0f) * 0.5f), 0.0f, 3.0f), -ImClamp(IM_FLOOR((bb_frame_height - 2.0f) * 0.5f), 0.0f, 3.0f)));

    // V denote the main, longer axis of the scrollbar (= height for a vertical scrollbar)
    const float scrollbar_size_v = (axis == SegaUiAxis_X) ? bb.GetWidth() : bb.GetHeight();

    // Calculate the height of our grabbable box. It generally represent the amount visible (vs the total scrollable amount)
    // But we maintain a minimum size in pixel to allow for the user to still aim inside.
    IM_ASSERT(ImMax(size_contents_v, size_avail_v) > 0.0f); // Adding this assert to check if the ImMax(XXX,1.0f) is still needed. PLEASE CONTACT ME if this triggers.
    const ImS64 win_size_v = ImMax(ImMax(size_contents_v, size_avail_v), (ImS64)1);
    const float grab_h_pixels = ImClamp(scrollbar_size_v * ((float)size_avail_v / (float)win_size_v), style.GrabMinSize, scrollbar_size_v);
    const float grab_h_norm = grab_h_pixels / scrollbar_size_v;

    // Handle input right away. None of the code of Begin() is relying on scrolling position before calling Scrollbar().
    bool held = false;
    bool hovered = false;
    ItemAdd(bb_frame, id, NULL, SegaUiItemFlags_NoNav);
    ButtonBehavior(bb, id, &hovered, &held, SegaUiButtonFlags_NoNavFocus);

    const ImS64 scroll_max = ImMax((ImS64)1, size_contents_v - size_avail_v);
    float scroll_ratio = ImSaturate((float)*p_scroll_v / (float)scroll_max);
    float grab_v_norm = scroll_ratio * (scrollbar_size_v - grab_h_pixels) / scrollbar_size_v; // Grab position in normalized space
    if (held && allow_interaction && grab_h_norm < 1.0f)
    {
        const float scrollbar_pos_v = bb.Min[axis];
        const float mouse_pos_v = g.IO.MousePos[axis];

        // Click position in scrollbar normalized space (0.0f->1.0f)
        const float clicked_v_norm = ImSaturate((mouse_pos_v - scrollbar_pos_v) / scrollbar_size_v);
        SetHoveredID(id);

        bool seek_absolute = false;
        if (g.ActiveIdIsJustActivated)
        {
            // On initial click calculate the distance between mouse and the center of the grab
            seek_absolute = (clicked_v_norm < grab_v_norm || clicked_v_norm > grab_v_norm + grab_h_norm);
            if (seek_absolute)
                g.ScrollbarClickDeltaToGrabCenter = 0.0f;
            else
                g.ScrollbarClickDeltaToGrabCenter = clicked_v_norm - grab_v_norm - grab_h_norm * 0.5f;
        }

        // Apply scroll (p_scroll_v will generally point on one member of window->Scroll)
        // It is ok to modify Scroll here because we are being called in Begin() after the calculation of ContentSize and before setting up our starting position
        const float scroll_v_norm = ImSaturate((clicked_v_norm - g.ScrollbarClickDeltaToGrabCenter - grab_h_norm * 0.5f) / (1.0f - grab_h_norm));
        *p_scroll_v = (ImS64)(scroll_v_norm * scroll_max);

        // Update values for rendering
        scroll_ratio = ImSaturate((float)*p_scroll_v / (float)scroll_max);
        grab_v_norm = scroll_ratio * (scrollbar_size_v - grab_h_pixels) / scrollbar_size_v;

        // Update distance to grab now that we have seeked and saturated
        if (seek_absolute)
            g.ScrollbarClickDeltaToGrabCenter = clicked_v_norm - grab_v_norm - grab_h_norm * 0.5f;
    }

    ImRect grab_rect;
    if (axis == SegaUiAxis_X)
        grab_rect = ImRect(ImLerp(bb.Min.x, bb.Max.x, grab_v_norm), bb.Min.y, ImLerp(bb.Min.x, bb.Max.x, grab_v_norm) + grab_h_pixels, bb.Max.y);
    else
        grab_rect = ImRect(bb.Min.x, ImLerp(bb.Min.y, bb.Max.y, grab_v_norm), bb.Max.x, ImLerp(bb.Min.y, bb.Max.y, grab_v_norm) + grab_h_pixels);

    window->DrawList->AddRectFilled(grab_rect.Min, grab_rect.Max, GetColorU32(c::accent), c::scroll::rounding);

    return held;
}

void SegaUi::Image(ImTextureID user_texture_id, const ImVec2& size, const ImVec2& uv0, const ImVec2& uv1, const ImVec4& tint_col, const ImVec4& border_col)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size);
    if (border_col.w > 0.0f)
        bb.Max += ImVec2(2, 2);
    ItemSize(bb);
    if (!ItemAdd(bb, 0))
        return;

    if (border_col.w > 0.0f)
    {
        window->DrawList->AddRect(bb.Min, bb.Max, GetColorU32(border_col), 0.0f);
        window->DrawList->AddImage(user_texture_id, bb.Min + ImVec2(1, 1), bb.Max - ImVec2(1, 1), uv0, uv1, GetColorU32(tint_col));
    }
    else
    {
        window->DrawList->AddImage(user_texture_id, bb.Min, bb.Max, uv0, uv1, GetColorU32(tint_col));
    }
}

// ImageButton() is flawed as 'id' is always derived from 'texture_id' (see #2464 #1390)
// We provide this internal helper to write your own variant while we figure out how to redesign the public ImageButton() API.
bool SegaUi::ImageButtonEx(SegaUiID id, ImTextureID texture_id, const ImVec2& size, const ImVec2& uv0, const ImVec2& uv1, const ImVec4& bg_col, const ImVec4& tint_col, SegaUiButtonFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const ImVec2 padding = g.Style.FramePadding;
    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size + padding * 2.0f);
    ItemSize(bb);
    if (!ItemAdd(bb, id))
        return false;

    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, flags);

    // Render
    const ImU32 col = GetColorU32((held && hovered) ? SegaUiCol_ButtonActive : hovered ? SegaUiCol_ButtonHovered : SegaUiCol_Button);
    RenderNavHighlight(bb, id);
    RenderFrame(bb.Min, bb.Max, col, true, ImClamp((float)ImMin(padding.x, padding.y), 0.0f, g.Style.FrameRounding));
    if (bg_col.w > 0.0f)
        window->DrawList->AddRectFilled(bb.Min + padding, bb.Max - padding, GetColorU32(bg_col));
    window->DrawList->AddImage(texture_id, bb.Min + padding, bb.Max - padding, uv0, uv1, GetColorU32(tint_col));

    return pressed;
}

bool SegaUi::ImageButton(const char* str_id, ImTextureID user_texture_id, const ImVec2& size, const ImVec2& uv0, const ImVec2& uv1, const ImVec4& bg_col, const ImVec4& tint_col)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    return ImageButtonEx(window->GetID(str_id), user_texture_id, size, uv0, uv1, bg_col, tint_col);
}

#ifndef SEGAUI_DISABLE_OBSOLETE_FUNCTIONS
// Legacy API obsoleted in 1.89. Two differences with new ImageButton()
// - new ImageButton() requires an explicit 'const char* str_id'    Old ImageButton() used opaque imTextureId (created issue with: multiple buttons with same image, transient texture id values, opaque computation of ID)
// - new ImageButton() always use style.FramePadding                Old ImageButton() had an override argument.
// If you need to change padding with new ImageButton() you can use PushStyleVar(SegaUiStyleVar_FramePadding, value), consistent with other Button functions.
bool SegaUi::ImageButton(ImTextureID user_texture_id, const ImVec2& size, const ImVec2& uv0, const ImVec2& uv1, int frame_padding, const ImVec4& bg_col, const ImVec4& tint_col)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    // Default to using texture ID as ID. User can still push string/integer prefixes.
    PushID((void*)(intptr_t)user_texture_id);
    const SegaUiID id = window->GetID("#image");
    PopID();

    if (frame_padding >= 0)
        PushStyleVar(SegaUiStyleVar_FramePadding, ImVec2((float)frame_padding, (float)frame_padding));
    bool ret = ImageButtonEx(id, user_texture_id, size, uv0, uv1, bg_col, tint_col);
    if (frame_padding >= 0)
        PopStyleVar();
    return ret;
}
#endif // #ifndef SEGAUI_DISABLE_OBSOLETE_FUNCTIONS

struct checkbox_state
{
    ImVec4 background, circle, text;
    float slow_circle;
};

bool SegaUi::Checkbox(const char* label, bool* v)
{
    SegaUiWindow* window = GetCurrentWindow();

    if (window->SkipItems) return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    const float w = SegaUi::GetContentRegionMax().x - style.WindowPadding.x * 2;

    const float square_sz = 12;
    const ImVec2 pos = window->DC.CursorPos;
    const ImRect total_bb(pos, pos + ImVec2(square_sz + w, label_size.y));
    ItemSize(total_bb, 0.f);

    if (!ItemAdd(total_bb, id)) return false;
    

    bool hovered, held, pressed = ButtonBehavior(total_bb, id, &hovered, &held);
    if (IsItemClicked())
    {
        PlaySound(TEXT("C:/ProgramData/MinecraftClickButtonSound.wav"), NULL, SND_FILENAME | SND_ASYNC);

        *v = !(*v);
        MarkItemEdited(id);
    }

    static std::map<SegaUiID, checkbox_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, checkbox_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.circle = ImLerp(it_anim->second.circle, *v ? c::accent : c::checkbox::circle_inactive, g.IO.DeltaTime * 6.f);
    it_anim->second.text = ImLerp(it_anim->second.text, *v ? c::text::text_active : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);
    it_anim->second.slow_circle = ImLerp(it_anim->second.slow_circle, *v ? -15.f : 0.f, g.IO.DeltaTime * 6.f);

    const ImRect check_bb(pos, pos + ImVec2(square_sz, square_sz));

    GetWindowDrawList()->AddRectFilled(check_bb.Min + ImVec2((w - 20), 0), check_bb.Max + ImVec2(w, 0), GetColorU32(c::checkbox::background), c::checkbox::rounding);
    GetWindowDrawList()->AddRectFilled(check_bb.Min + ImVec2((w - 20 - it_anim->second.slow_circle), -3), check_bb.Max + ImVec2(w - 15 - it_anim->second.slow_circle, 3), GetColorU32(it_anim->second.circle), c::checkbox::rounding);

    if (*v) GetWindowDrawList()->AddShadowRect(check_bb.Min + ImVec2((w - 20 - it_anim->second.slow_circle), -3), check_bb.Max + ImVec2(w - 15 - it_anim->second.slow_circle, 3), GetColorU32(it_anim->second.circle), 10.f, ImVec2(0, 0), c::picker::rounding);

    GlowText(font::inter_default, 17.f, label, ImVec2(check_bb.Max.x - square_sz, check_bb.Min.y - 2), GetColorU32(it_anim->second.text));

    //GetWindowDrawList()->AddText(ImVec2(check_bb.Max.x - square_sz, check_bb.Min.y - 2), GetColorU32(it_anim->second.text), label);

    return pressed;
}
//
//void SegaUi::Pickerbox(const char* label, bool* v, float color[3], SegaUiColorEditFlags flags)
//{
//    std::string label_key = "picker", label_bind = label_key + label;
//
//    ImVec2 Start = GetCursorPos();
//    SegaUi::SetCursorPos(GetCursorPos() - ImVec2(55, 8));
//    SegaUi::ColorEdit4(label_bind.c_str(), color, flags | SegaUiColorEditFlags_NoLabel);
//
//    SegaUi::SetCursorPos(GetCursorPos() - ImVec2(0, GetStyle().ItemSpacing.y * 2 - 8));
//    SegaUi::Checkbox(label, v);
//
//}


void SegaUi::Pickerbox(const char* label, bool* v, float color[3], SegaUiColorEditFlags flags)
{
    std::string label_key = "picker", label_bind = label_key + label;

    ImVec2 Start = GetCursorPos();

    SegaUi::SetCursorPos(Start - ImVec2(55, 0));

    //SegaUi::SetCursorPos(Start - ImVec2(0, GetStyle().ItemSpacing.y * 2 - 8));
    SegaUi::ColorEdit4(label_bind.c_str(), color, flags | SegaUiColorEditFlags_NoLabel);

    SegaUi::SetCursorPos(Start + ImVec2(0, 4));


    SegaUi::Checkbox(label, v);


}

//void SegaUi::Keybindbox(const char* label, bool* v, int *key, int* m)
//{
//    std::string label_key = "bind", label_bind = label_key + label;
//
//    SegaUi::SetCursorPos(GetCursorPos() - ImVec2(55,8));
//    SegaUi::Keybind(label_bind.c_str(), key, m, false);
//
//    SegaUi::SetCursorPos(GetCursorPos() - ImVec2(0, GetStyle().ItemSpacing.y * 2 - 8));
//    SegaUi::Checkbox(label, v);
//}

void SegaUi::Keybindbox(const char* label, bool* v, int* key, int* m)
{
    std::string label_key = "bind", label_bind = label_key + label;

    //SegaUi::SetCursorPos(GetCursorPos() - ImVec2(0, GetStyle().ItemSpacing.y * 2 - 8));
    SegaUi::Checkbox(label, v);
    SegaUi::Keybind(label_bind.c_str(), key, m, false);

}

template<typename T>
bool SegaUi::CheckboxFlagsT(const char* label, T* flags, T flags_value)
{
    bool all_on = (*flags & flags_value) == flags_value;
    bool any_on = (*flags & flags_value) != 0;
    bool pressed;
    if (!all_on && any_on)
    {
        SegaUiContext& g = *GSegaUi;
        SegaUiItemFlags backup_item_flags = g.CurrentItemFlags;
        g.CurrentItemFlags |= SegaUiItemFlags_MixedValue;
        pressed = Checkbox(label, &all_on);
        g.CurrentItemFlags = backup_item_flags;
    }
    else
    {
        pressed = Checkbox(label, &all_on);

    }
    if (pressed)
    {
        if (all_on)
            *flags |= flags_value;
        else
            *flags &= ~flags_value;
    }
    return pressed;
}

bool SegaUi::CheckboxFlags(const char* label, int* flags, int flags_value)
{
    return CheckboxFlagsT(label, flags, flags_value);
}

bool SegaUi::CheckboxFlags(const char* label, unsigned int* flags, unsigned int flags_value)
{
    return CheckboxFlagsT(label, flags, flags_value);
}

bool SegaUi::CheckboxFlags(const char* label, ImS64* flags, ImS64 flags_value)
{
    return CheckboxFlagsT(label, flags, flags_value);
}

bool SegaUi::CheckboxFlags(const char* label, ImU64* flags, ImU64 flags_value)
{
    return CheckboxFlagsT(label, flags, flags_value);
}

bool SegaUi::RadioButton(const char* label, bool active)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    const float square_sz = GetFrameHeight();
    const ImVec2 pos = window->DC.CursorPos;
    const ImRect check_bb(pos, pos + ImVec2(square_sz, square_sz));
    const ImRect total_bb(pos, pos + ImVec2(square_sz + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f), label_size.y + style.FramePadding.y * 2.0f));
    ItemSize(total_bb, style.FramePadding.y);
    if (!ItemAdd(total_bb, id))
        return false;

    ImVec2 center = check_bb.GetCenter();
    center.x = IM_ROUND(center.x);
    center.y = IM_ROUND(center.y);
    const float radius = (square_sz - 1.0f) * 0.5f;

    bool hovered, held;
    bool pressed = ButtonBehavior(total_bb, id, &hovered, &held);
    if (pressed)
        MarkItemEdited(id);

    RenderNavHighlight(total_bb, id);
    const int num_segment = window->DrawList->_CalcCircleAutoSegmentCount(radius);
    window->DrawList->AddCircleFilled(center, radius, GetColorU32((held && hovered) ? SegaUiCol_FrameBgActive : hovered ? SegaUiCol_FrameBgHovered : SegaUiCol_FrameBg), num_segment);
    if (active)
    {
        const float pad = ImMax(1.0f, IM_FLOOR(square_sz / 6.0f));
        window->DrawList->AddCircleFilled(center, radius - pad, GetColorU32(SegaUiCol_CheckMark));
    }

    if (style.FrameBorderSize > 0.0f)
    {
        window->DrawList->AddCircle(center + ImVec2(1, 1), radius, GetColorU32(SegaUiCol_BorderShadow), num_segment, style.FrameBorderSize);
        window->DrawList->AddCircle(center, radius, GetColorU32(SegaUiCol_Border), num_segment, style.FrameBorderSize);
    }

    ImVec2 label_pos = ImVec2(check_bb.Max.x + style.ItemInnerSpacing.x, check_bb.Min.y + style.FramePadding.y);
    if (g.LogEnabled)
        LogRenderedText(&label_pos, active ? "(x)" : "( )");
    if (label_size.x > 0.0f)
        RenderText(label_pos, label);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags);
    return pressed;
}

// FIXME: This would work nicely if it was a public template, e.g. 'template<T> RadioButton(const char* label, T* v, T v_button)', but I'm not sure how we would expose it..
bool SegaUi::RadioButton(const char* label, int* v, int v_button)
{
    const bool pressed = RadioButton(label, *v == v_button);
    if (pressed)
        *v = v_button;
    return pressed;
}

// size_arg (for each axis) < 0.0f: align to end, 0.0f: auto, > 0.0f: specified size
void SegaUi::ProgressBar(float fraction, const ImVec2& size_arg, const char* overlay)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;

    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = CalcItemSize(size_arg, CalcItemWidth(), g.FontSize + style.FramePadding.y * 2.0f);
    ImRect bb(pos, pos + size);
    ItemSize(size, style.FramePadding.y);
    if (!ItemAdd(bb, 0))
        return;

    // Render
    fraction = ImSaturate(fraction);
    RenderFrame(bb.Min, bb.Max, GetColorU32(SegaUiCol_FrameBg), true, style.FrameRounding);
    bb.Expand(ImVec2(-style.FrameBorderSize, -style.FrameBorderSize));
    const ImVec2 fill_br = ImVec2(ImLerp(bb.Min.x, bb.Max.x, fraction), bb.Max.y);
    RenderRectFilledRangeH(window->DrawList, bb, GetColorU32(SegaUiCol_PlotHistogram), 0.0f, fraction, style.FrameRounding);

    // Default displaying the fraction as percentage string, but user can override it
    char overlay_buf[32];
    if (!overlay)
    {
        ImFormatString(overlay_buf, IM_ARRAYSIZE(overlay_buf), "%.0f%%", fraction * 100 + 0.01f);
        overlay = overlay_buf;
    }

    ImVec2 overlay_size = CalcTextSize(overlay, NULL);
    if (overlay_size.x > 0.0f)
        RenderTextClipped(ImVec2(ImClamp(fill_br.x + style.ItemSpacing.x, bb.Min.x, bb.Max.x - overlay_size.x - style.ItemInnerSpacing.x), bb.Min.y), bb.Max, overlay, NULL, &overlay_size, ImVec2(0.0f, 0.5f), &bb);
}

void SegaUi::Bullet()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const float line_height = ImMax(ImMin(window->DC.CurrLineSize.y, g.FontSize + style.FramePadding.y * 2), g.FontSize);
    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + ImVec2(g.FontSize, line_height));
    ItemSize(bb);
    if (!ItemAdd(bb, 0))
    {
        SameLine(0, style.FramePadding.x * 2);
        return;
    }

    // Render and stay on same line
    ImU32 text_col = GetColorU32(SegaUiCol_Text);
    RenderBullet(window->DrawList, bb.Min + ImVec2(style.FramePadding.x + g.FontSize * 0.5f, line_height * 0.5f), text_col);
    SameLine(0, style.FramePadding.x * 2.0f);
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: Low-level Layout helpers
//-------------------------------------------------------------------------
// - Spacing()
// - Dummy()
// - NewLine()
// - AlignTextToFramePadding()
// - SeparatorEx() [Internal]
// - Separator()
// - SplitterBehavior() [Internal]
// - ShrinkWidths() [Internal]
//-------------------------------------------------------------------------

void SegaUi::Spacing()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;
    ItemSize(ImVec2(0, 0));
}

void SegaUi::Dummy(const ImVec2& size)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + size);
    ItemSize(size);
    ItemAdd(bb, 0);
}

void SegaUi::NewLine()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    const SegaUiLayoutType backup_layout_type = window->DC.LayoutType;
    window->DC.LayoutType = SegaUiLayoutType_Vertical;
    window->DC.IsSameLine = false;
    if (window->DC.CurrLineSize.y > 0.0f)     // In the event that we are on a line with items that is smaller that FontSize high, we will preserve its height.
        ItemSize(ImVec2(0, 0));
    else
        ItemSize(ImVec2(0.0f, g.FontSize));
    window->DC.LayoutType = backup_layout_type;
}

void SegaUi::AlignTextToFramePadding()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    window->DC.CurrLineSize.y = ImMax(window->DC.CurrLineSize.y, g.FontSize + g.Style.FramePadding.y * 2);
    window->DC.CurrLineTextBaseOffset = ImMax(window->DC.CurrLineTextBaseOffset, g.Style.FramePadding.y);
}

// Horizontal/vertical separating line
// FIXME: Surprisingly, this seemingly simple widget is adjacent to MANY different legacy/tricky layout issues.
void SegaUi::SeparatorEx(SegaUiSeparatorFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    SegaUiContext& g = *GSegaUi;
    IM_ASSERT(ImIsPowerOfTwo(flags & (SegaUiSeparatorFlags_Horizontal | SegaUiSeparatorFlags_Vertical)));   // Check that only 1 option is selected

    const float thickness = 1.0f; // Cannot use g.Style.SeparatorTextSize yet for various reasons.
    if (flags & SegaUiSeparatorFlags_Vertical)
    {
        // Vertical separator, for menu bars (use current line height).
        float y1 = window->DC.CursorPos.y;
        float y2 = window->DC.CursorPos.y + window->DC.CurrLineSize.y;
        const ImRect bb(ImVec2(window->DC.CursorPos.x, y1), ImVec2(window->DC.CursorPos.x + thickness, y2));
        ItemSize(ImVec2(thickness, 0.0f));
        if (!ItemAdd(bb, 0))
            return;

        // Draw
        window->DrawList->AddRectFilled(bb.Min, bb.Max, GetColorU32(SegaUiCol_Separator));
        if (g.LogEnabled)
            LogText(" |");
    }
    else if (flags & SegaUiSeparatorFlags_Horizontal)
    {
        // Horizontal Separator
        float x1 = window->Pos.x;
        float x2 = window->Pos.x + window->Size.x;

        // FIXME-WORKRECT: old hack (#205) until we decide of consistent behavior with WorkRect/Indent and Separator
        if (g.GroupStack.Size > 0 && g.GroupStack.back().WindowID == window->ID)
            x1 += window->DC.Indent.x;

        // FIXME-WORKRECT: In theory we should simply be using WorkRect.Min.x/Max.x everywhere but it isn't aesthetically what we want,
        // need to introduce a variant of WorkRect for that purpose. (#4787)
        if (SegaUiTable* table = g.CurrentTable)
        {
            x1 = table->Columns[table->CurrentColumn].MinX;
            x2 = table->Columns[table->CurrentColumn].MaxX;
        }

        SegaUiOldColumns* columns = (flags & SegaUiSeparatorFlags_SpanAllColumns) ? window->DC.CurrentColumns : NULL;
        if (columns)
            PushColumnsBackground();

        // We don't provide our width to the layout so that it doesn't get feed back into AutoFit
        // FIXME: This prevents ->CursorMaxPos based bounding box evaluation from working (e.g. TableEndCell)
        const float thickness_for_layout = (thickness == 1.0f) ? 0.0f : thickness; // FIXME: See 1.70/1.71 Separator() change: makes legacy 1-px separator not affect layout yet. Should change.
        const ImRect bb(ImVec2(x1, window->DC.CursorPos.y), ImVec2(x2, window->DC.CursorPos.y + thickness));
        ItemSize(ImVec2(0.0f, thickness_for_layout));
        const bool item_visible = ItemAdd(bb, 0);
        if (item_visible)
        {
            // Draw
            window->DrawList->AddRectFilled(bb.Min, bb.Max, GetColorU32(SegaUiCol_Separator));
            if (g.LogEnabled)
                LogRenderedText(&bb.Min, "--------------------------------\n");

        }
        if (columns)
        {
            PopColumnsBackground();
            columns->LineMinY = window->DC.CursorPos.y;
        }
    }
}

void SegaUi::Separator()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return;

    // Those flags should eventually be overridable by the user
    SegaUiSeparatorFlags flags = (window->DC.LayoutType == SegaUiLayoutType_Horizontal) ? SegaUiSeparatorFlags_Vertical : SegaUiSeparatorFlags_Horizontal;
    flags |= SegaUiSeparatorFlags_SpanAllColumns; // NB: this only applies to legacy Columns() api as they relied on Separator() a lot.
    SeparatorEx(flags);
}

void SegaUi::SeparatorTextEx(SegaUiID id, const char* label, const char* label_end, float extra_w)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    SegaUiStyle& style = g.Style;

    const ImVec2 label_size = CalcTextSize(label, label_end, false);
    const ImVec2 pos = window->DC.CursorPos;
    const ImVec2 padding = style.SeparatorTextPadding;

    const float separator_thickness = style.SeparatorTextBorderSize;
    const ImVec2 min_size(label_size.x + extra_w + padding.x * 2.0f, ImMax(label_size.y + padding.y * 2.0f, separator_thickness));
    const ImRect bb(pos, ImVec2(window->WorkRect.Max.x, pos.y + min_size.y));
    const float text_baseline_y = ImFloor((bb.GetHeight() - label_size.y) * style.SeparatorTextAlign.y + 0.99999f); //ImMax(padding.y, ImFloor((style.SeparatorTextSize - label_size.y) * 0.5f));
    ItemSize(min_size, text_baseline_y);
    if (!ItemAdd(bb, id))
        return;

    const float sep1_x1 = pos.x;
    const float sep2_x2 = bb.Max.x;
    const float seps_y = ImFloor((bb.Min.y + bb.Max.y) * 0.5f + 0.99999f);

    const float label_avail_w = ImMax(0.0f, sep2_x2 - sep1_x1 - padding.x * 2.0f);
    const ImVec2 label_pos(pos.x + padding.x + ImMax(0.0f, (label_avail_w - label_size.x - extra_w) * style.SeparatorTextAlign.x), pos.y + text_baseline_y); // FIXME-ALIGN

    // This allows using SameLine() to position something in the 'extra_w'
    window->DC.CursorPosPrevLine.x = label_pos.x + label_size.x;

    const ImU32 separator_col = GetColorU32(SegaUiCol_Separator);
    if (label_size.x > 0.0f)
    {
        const float sep1_x2 = label_pos.x - style.ItemSpacing.x;
        const float sep2_x1 = label_pos.x + label_size.x + extra_w + style.ItemSpacing.x;
        if (sep1_x2 > sep1_x1 && separator_thickness > 0.0f)
            window->DrawList->AddLine(ImVec2(sep1_x1, seps_y), ImVec2(sep1_x2, seps_y), separator_col, separator_thickness);
        if (sep2_x2 > sep2_x1 && separator_thickness > 0.0f)
            window->DrawList->AddLine(ImVec2(sep2_x1, seps_y), ImVec2(sep2_x2, seps_y), separator_col, separator_thickness);
        if (g.LogEnabled)
            LogSetNextTextDecoration("---", NULL);
        RenderTextEllipsis(window->DrawList, label_pos, ImVec2(bb.Max.x, bb.Max.y + style.ItemSpacing.y), bb.Max.x, bb.Max.x, label, label_end, &label_size);
    }
    else
    {
        if (g.LogEnabled)
            LogText("---");
        if (separator_thickness > 0.0f)
            window->DrawList->AddLine(ImVec2(sep1_x1, seps_y), ImVec2(sep2_x2, seps_y), separator_col, separator_thickness);
    }
}

void SegaUi::SeparatorText(const char* label)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;

    // The SeparatorText() vs SeparatorTextEx() distinction is designed to be considerate that we may want:
    // - allow headers to be draggable items (would require a stable ID + a noticeable highlight)
    // - this high-level entry point to allow formatting? (may require ID separate from formatted string)
    // - because of this we probably can't turn 'const char* label' into 'const char* fmt, ...'
    // Otherwise, we can decide that users wanting to drag this would layout a dedicated drag-item,
    // and then we can turn this into a format function.
    SeparatorTextEx(0, label, FindRenderedTextEnd(label), 0.0f);
}

// Using 'hover_visibility_delay' allows us to hide the highlight and mouse cursor for a short time, which can be convenient to reduce visual noise.
bool SegaUi::SplitterBehavior(const ImRect& bb, SegaUiID id, SegaUiAxis axis, float* size1, float* size2, float min_size1, float min_size2, float hover_extend, float hover_visibility_delay, ImU32 bg_col)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;

    if (!ItemAdd(bb, id, NULL, SegaUiItemFlags_NoNav))
        return false;

    bool hovered, held;
    ImRect bb_interact = bb;
    bb_interact.Expand(axis == SegaUiAxis_Y ? ImVec2(0.0f, hover_extend) : ImVec2(hover_extend, 0.0f));
    ButtonBehavior(bb_interact, id, &hovered, &held, SegaUiButtonFlags_FlattenChildren | SegaUiButtonFlags_AllowItemOverlap);
    if (hovered)
        g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_HoveredRect; // for IsItemHovered(), because bb_interact is larger than bb
    if (g.ActiveId != id)
        SetItemAllowOverlap();

    if (held || (hovered && g.HoveredIdPreviousFrame == id && g.HoveredIdTimer >= hover_visibility_delay))
        SetMouseCursor(axis == SegaUiAxis_Y ? SegaUiMouseCursor_ResizeNS : SegaUiMouseCursor_ResizeEW);

    ImRect bb_render = bb;
    if (held)
    {
        ImVec2 mouse_delta_2d = g.IO.MousePos - g.ActiveIdClickOffset - bb_interact.Min;
        float mouse_delta = (axis == SegaUiAxis_Y) ? mouse_delta_2d.y : mouse_delta_2d.x;

        // Minimum pane size
        float size_1_maximum_delta = ImMax(0.0f, *size1 - min_size1);
        float size_2_maximum_delta = ImMax(0.0f, *size2 - min_size2);
        if (mouse_delta < -size_1_maximum_delta)
            mouse_delta = -size_1_maximum_delta;
        if (mouse_delta > size_2_maximum_delta)
            mouse_delta = size_2_maximum_delta;

        // Apply resize
        if (mouse_delta != 0.0f)
        {
            if (mouse_delta < 0.0f)
                IM_ASSERT(*size1 + mouse_delta >= min_size1);
            if (mouse_delta > 0.0f)
                IM_ASSERT(*size2 - mouse_delta >= min_size2);
            *size1 += mouse_delta;
            *size2 -= mouse_delta;
            bb_render.Translate((axis == SegaUiAxis_X) ? ImVec2(mouse_delta, 0.0f) : ImVec2(0.0f, mouse_delta));
            MarkItemEdited(id);
        }
    }

    // Render at new position
    if (bg_col & IM_COL32_A_MASK)
        window->DrawList->AddRectFilled(bb_render.Min, bb_render.Max, bg_col, 0.0f);
    const ImU32 col = GetColorU32(held ? SegaUiCol_SeparatorActive : (hovered && g.HoveredIdTimer >= hover_visibility_delay) ? SegaUiCol_SeparatorHovered : SegaUiCol_Separator);
    window->DrawList->AddRectFilled(bb_render.Min, bb_render.Max, col, 0.0f);

    return held;
}

static int SEGAUI_CDECL ShrinkWidthItemComparer(const void* lhs, const void* rhs)
{
    const SegaUiShrinkWidthItem* a = (const SegaUiShrinkWidthItem*)lhs;
    const SegaUiShrinkWidthItem* b = (const SegaUiShrinkWidthItem*)rhs;
    if (int d = (int)(b->Width - a->Width))
        return d;
    return (b->Index - a->Index);
}

// Shrink excess width from a set of item, by removing width from the larger items first.
// Set items Width to -1.0f to disable shrinking this item.
void SegaUi::ShrinkWidths(SegaUiShrinkWidthItem* items, int count, float width_excess)
{
    if (count == 1)
    {
        if (items[0].Width >= 0.0f)
            items[0].Width = ImMax(items[0].Width - width_excess, 1.0f);
        return;
    }
    ImQsort(items, (size_t)count, sizeof(SegaUiShrinkWidthItem), ShrinkWidthItemComparer);
    int count_same_width = 1;
    while (width_excess > 0.0f && count_same_width < count)
    {
        while (count_same_width < count && items[0].Width <= items[count_same_width].Width)
            count_same_width++;
        float max_width_to_remove_per_item = (count_same_width < count && items[count_same_width].Width >= 0.0f) ? (items[0].Width - items[count_same_width].Width) : (items[0].Width - 1.0f);
        if (max_width_to_remove_per_item <= 0.0f)
            break;
        float width_to_remove_per_item = ImMin(width_excess / count_same_width, max_width_to_remove_per_item);
        for (int item_n = 0; item_n < count_same_width; item_n++)
            items[item_n].Width -= width_to_remove_per_item;
        width_excess -= width_to_remove_per_item * count_same_width;
    }

    // Round width and redistribute remainder
    // Ensure that e.g. the right-most tab of a shrunk tab-bar always reaches exactly at the same distance from the right-most edge of the tab bar separator.
    width_excess = 0.0f;
    for (int n = 0; n < count; n++)
    {
        float width_rounded = ImFloor(items[n].Width);
        width_excess += items[n].Width - width_rounded;
        items[n].Width = width_rounded;
    }
    while (width_excess > 0.0f)
        for (int n = 0; n < count && width_excess > 0.0f; n++)
        {
            float width_to_add = ImMin(items[n].InitialWidth - items[n].Width, 1.0f);
            items[n].Width += width_to_add;
            width_excess -= width_to_add;
        }
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: ComboBox
//-------------------------------------------------------------------------
// - CalcMaxPopupHeightFromItemCount() [Internal]
// - BeginCombo()
// - BeginComboPopup() [Internal]
// - EndCombo()
// - BeginComboPreview() [Internal]
// - EndComboPreview() [Internal]
// - Combo()
//-------------------------------------------------------------------------

static float CalcMaxPopupHeightFromItemCount(int items_count)
{
    SegaUiContext& g = *GSegaUi;
    if (items_count <= 0)
        return FLT_MAX;
    return (g.FontSize + g.Style.ItemSpacing.y) * items_count - g.Style.ItemSpacing.y + (g.Style.WindowPadding.y * 2);
}

struct combo_state {

    ImVec4 background, text, icon, outline;
    float combo_size = 0.f;
    bool opened_combo = false, hovered;
};

namespace pic
{
    extern ID3D11ShaderResourceView* combo_widget;
    extern ID3D11ShaderResourceView* input_widget;

}

bool SegaUi::BeginCombo(const char* label, const char* preview_value, float val, bool multi, SegaUiComboFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();

    SegaUiNextWindowDataFlags backup_next_window_data_flags = g.NextWindowData.Flags;
    g.NextWindowData.ClearFlags();

    if (window->SkipItems) return false;

    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    IM_ASSERT((flags & (SegaUiComboFlags_NoArrowButton | SegaUiComboFlags_NoPreview)) != (SegaUiComboFlags_NoArrowButton | SegaUiComboFlags_NoPreview)); // Can't use both flags together

    const float arrow_size = (flags & SegaUiComboFlags_NoArrowButton) ? 0.0f : GetFrameHeight();
    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const float w = GetContentRegionMax().x - style.WindowPadding.x;

    const ImRect bb(window->DC.CursorPos, window->DC.CursorPos + ImVec2(w, 40));
    const ImRect total_bb(bb.Min, bb.Max + ImVec2(label_size.x, 0));
    ItemSize(total_bb, 0.f);

    if (!ItemAdd(total_bb, id, &bb)) return false;

    const SegaUiID popup_id = ImHashStr("##ComboPopup", 0, id);

    bool hovered, held, pressed = ButtonBehavior(bb, id, &hovered, &held);

    static std::map<SegaUiID, combo_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, combo_state() });
        it_anim = anim.find(id);
    }

    if (hovered && g.IO.MouseClicked[0] || it_anim->second.opened_combo && g.IO.MouseClicked[0] && !it_anim->second.hovered) it_anim->second.opened_combo = !it_anim->second.opened_combo;
    it_anim->second.combo_size = ImLerp(it_anim->second.combo_size, it_anim->second.opened_combo ? (val * 30) + 4 : 0.f, g.IO.DeltaTime * 12.f);
    it_anim->second.outline = ImLerp(it_anim->second.outline, it_anim->second.opened_combo ? c::accent : c::combo::outline, g.IO.DeltaTime * 12.f);
    it_anim->second.icon = ImLerp(it_anim->second.icon, it_anim->second.opened_combo ? c::accent : c::combo::icon, g.IO.DeltaTime * 12.f);

    it_anim->second.text = ImLerp(it_anim->second.text, it_anim->second.opened_combo ? c::text::text_active : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);

    const float value_x2 = ImMax(bb.Min.x, bb.Max.x - arrow_size);

    GetWindowDrawList()->AddRectFilled(bb.Min, bb.Max, GetColorU32(it_anim->second.outline), c::combo::rounding);

    invisible_shadow(1.f, bb.Min, bb.Max, GetColorU32(c::accent), 500);

    GetWindowDrawList()->AddRectFilled(bb.Min + ImVec2(1, 1), bb.Max - ImVec2(1, 1), GetColorU32(c::combo::background), c::combo::rounding);

    GetWindowDrawList()->AddImage(pic::combo_widget, bb.Min + ImVec2(w - 30, (40 - 25) / 2), bb.Max - ImVec2(5, (40 - 25) / 2), ImVec2(0, 0), ImVec2(1, 1), SegaUi::GetColorU32(it_anim->second.icon));

    PushStyleColor(SegaUiCol_Text, GetColorU32(it_anim->second.text));
    RenderTextClipped(bb.Min + ImVec2(10, 0), ImVec2(value_x2, bb.Max.y), preview_value, NULL, NULL, ImVec2(0.0, 0.5), NULL);
    PopStyleColor();

    if (!IsRectVisible(bb.Min, bb.Max + ImVec2(0, 2)))
    {
        it_anim->second.opened_combo = false;
        it_anim->second.combo_size = 0.f;
    }

    if (!it_anim->second.opened_combo && it_anim->second.combo_size < 2.f)
        return false;

    SegaUi::SetNextWindowPos(ImVec2(bb.Min.x + 2, bb.Max.y + 8));
    SegaUi::SetNextWindowSize(ImVec2(bb.GetWidth() - 3, it_anim->second.combo_size));

    SegaUiWindowFlags window_flags = SegaUiWindowFlags_AlwaysAutoResize | SegaUiWindowFlags_NoTitleBar | SegaUiWindowFlags_NoResize | SegaUiWindowFlags_NoSavedSettings | SegaUiWindowFlags_NoMove | SegaUiWindowFlags_NoScrollbar | SegaUiWindowFlags_NoFocusOnAppearing | SegaUiWindowFlags_NoScrollWithMouse;

    PushStyleVar(SegaUiStyleVar_WindowPadding, ImVec2(10, 10));
    PushStyleVar(SegaUiStyleVar_WindowRounding, c::combo::rounding);
    PushStyleColor(SegaUiCol_WindowBg, GetColorU32(c::combo::background));

    bool ret = Begin(label, NULL, window_flags);
    PopStyleVar(2);
    PopStyleColor();

    it_anim->second.hovered = IsWindowHovered();

    if (multi && it_anim->second.hovered && g.IO.MouseClicked[0]) it_anim->second.opened_combo = false;

    return true;
}

void SegaUi::EndCombo()
{
    End();
}

void SegaUi::MultiCombo(const char* label, bool variable[], const char* labels[], int count)
{
    SegaUiContext& g = *GSegaUi;

    std::string preview = "None";

    for (auto i = 0, j = 0; i < count; i++)
    {
        if (variable[i])
        {
            if (j)
                preview += (", ") + (std::string)labels[i];
            else
                preview = labels[i];

            j++;
        }
    }

    PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(12, 12));
    if (SegaUi::BeginCombo(label, preview.c_str(), count)) // draw start
    {
        for (auto i = 0; i < count; i++)
            SegaUi::Selectable(labels[i], &variable[i], SegaUiSelectableFlags_DontClosePopups);
        End();
    }
    PopStyleVar();

    preview = ("None"); // reset preview to use later
}


// Call directly after the BeginCombo/EndCombo block. The preview is designed to only host non-interactive elements
// (Experimental, see GitHub issues: #1658, #4168)
bool SegaUi::BeginComboPreview()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    SegaUiComboPreviewData* preview_data = &g.ComboPreviewData;

    if (window->SkipItems || !(g.LastItemData.StatusFlags & SegaUiItemStatusFlags_Visible))
        return false;
    IM_ASSERT(g.LastItemData.Rect.Min.x == preview_data->PreviewRect.Min.x && g.LastItemData.Rect.Min.y == preview_data->PreviewRect.Min.y); // Didn't call after BeginCombo/EndCombo block or forgot to pass SegaUiComboFlags_CustomPreview flag?
    if (!window->ClipRect.Contains(preview_data->PreviewRect)) // Narrower test (optional)
        return false;

    // FIXME: This could be contained in a PushWorkRect() api
    preview_data->BackupCursorPos = window->DC.CursorPos;
    preview_data->BackupCursorMaxPos = window->DC.CursorMaxPos;
    preview_data->BackupCursorPosPrevLine = window->DC.CursorPosPrevLine;
    preview_data->BackupPrevLineTextBaseOffset = window->DC.PrevLineTextBaseOffset;
    preview_data->BackupLayout = window->DC.LayoutType;
    window->DC.CursorPos = preview_data->PreviewRect.Min + g.Style.FramePadding;
    window->DC.CursorMaxPos = window->DC.CursorPos;
    window->DC.LayoutType = SegaUiLayoutType_Horizontal;
    window->DC.IsSameLine = false;
    PushClipRect(preview_data->PreviewRect.Min, preview_data->PreviewRect.Max, true);

    return true;
}

void SegaUi::EndComboPreview()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    SegaUiComboPreviewData* preview_data = &g.ComboPreviewData;

    // FIXME: Using CursorMaxPos approximation instead of correct AABB which we will store in ImDrawCmd in the future
    ImDrawList* draw_list = window->DrawList;
    if (window->DC.CursorMaxPos.x < preview_data->PreviewRect.Max.x && window->DC.CursorMaxPos.y < preview_data->PreviewRect.Max.y)
        if (draw_list->CmdBuffer.Size > 1) // Unlikely case that the PushClipRect() didn't create a command
        {
            draw_list->_CmdHeader.ClipRect = draw_list->CmdBuffer[draw_list->CmdBuffer.Size - 1].ClipRect = draw_list->CmdBuffer[draw_list->CmdBuffer.Size - 2].ClipRect;
            draw_list->_TryMergeDrawCmds();
        }
    PopClipRect();
    window->DC.CursorPos = preview_data->BackupCursorPos;
    window->DC.CursorMaxPos = ImMax(window->DC.CursorMaxPos, preview_data->BackupCursorMaxPos);
    window->DC.CursorPosPrevLine = preview_data->BackupCursorPosPrevLine;
    window->DC.PrevLineTextBaseOffset = preview_data->BackupPrevLineTextBaseOffset;
    window->DC.LayoutType = preview_data->BackupLayout;
    window->DC.IsSameLine = false;
    preview_data->PreviewRect = ImRect();
}

// Getter for the old Combo() API: const char*[]
static bool Items_ArrayGetter(void* data, int idx, const char** out_text)
{
    const char* const* items = (const char* const*)data;
    if (out_text)
        *out_text = items[idx];
    return true;
}

// Getter for the old Combo() API: "item1\0item2\0item3\0"
static bool Items_SingleStringGetter(void* data, int idx, const char** out_text)
{
    // FIXME-OPT: we could pre-compute the indices to fasten this. But only 1 active combo means the waste is limited.
    const char* items_separated_by_zeros = (const char*)data;
    int items_count = 0;
    const char* p = items_separated_by_zeros;
    while (*p)
    {
        if (idx == items_count)
            break;
        p += strlen(p) + 1;
        items_count++;
    }
    if (!*p)
        return false;
    if (out_text)
        *out_text = p;
    return true;
}

// Old API, prefer using BeginCombo() nowadays if you can.
bool SegaUi::Combo(const char* label, int* current_item, bool (*items_getter)(void*, int, const char**), void* data, int items_count, int popup_max_height_in_items)
{
    SegaUiContext& g = *GSegaUi;

    // Call the getter to obtain the preview string which is a parameter to BeginCombo()
    const char* preview_value = NULL;
    if (*current_item >= 0 && *current_item < items_count)
        items_getter(data, *current_item, &preview_value);

    // The old Combo() API exposed "popup_max_height_in_items". The new more general BeginCombo() API doesn't have/need it, but we emulate it here.
    if (popup_max_height_in_items != -1 && !(g.NextWindowData.Flags & SegaUiNextWindowDataFlags_HasSizeConstraint))
        SetNextWindowSizeConstraints(ImVec2(0, 0), ImVec2(FLT_MAX, CalcMaxPopupHeightFromItemCount(popup_max_height_in_items)));

  
    if (!BeginCombo(label, preview_value, items_count, SegaUiComboFlags_None))
        return false;


    //if (!BeginCombo(label, preview_value, items_count, SegaUiComboFlags_None))
    //    return false;

    // Display items
    // FIXME-OPT: Use clipper (but we need to disable it on the appearing frame to make sure our call to SetItemDefaultFocus() is processed)
    bool value_changed = false;
    PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(12, 12));
    for (int i = 0; i < items_count; i++)
    {
        PushID(i);
        const bool item_selected = (i == *current_item);
        const char* item_text;
        if (!items_getter(data, i, &item_text))
            item_text = "*Unknown item*";
        if (Selectable(item_text, item_selected))
        {
            value_changed = true;
            *current_item = i;
        }
        if (item_selected)
            SetItemDefaultFocus();
        PopID();
    }
    PopStyleVar();
    EndCombo();

    if (value_changed)
        MarkItemEdited(g.LastItemData.ID);

    return value_changed;
}

// Combo box helper allowing to pass an array of strings.
bool SegaUi::Combo(const char* label, int* current_item, const char* const items[], int items_count, int height_in_items)
{
    const bool value_changed = Combo(label, current_item, Items_ArrayGetter, (void*)items, items_count, height_in_items);
    return value_changed;
}

// Combo box helper allowing to pass all items in a single string literal holding multiple zero-terminated items "item1\0item2\0"
bool SegaUi::Combo(const char* label, int* current_item, const char* items_separated_by_zeros, int height_in_items)
{
    int items_count = 0;
    const char* p = items_separated_by_zeros;       // FIXME-OPT: Avoid computing this, or at least only when combo is open
    while (*p)
    {
        p += strlen(p) + 1;
        items_count++;
    }
    bool value_changed = Combo(label, current_item, Items_SingleStringGetter, (void*)items_separated_by_zeros, items_count, height_in_items);
    return value_changed;
}


//-------------------------------------------------------------------------
// [SECTION] Data Type and Data Formatting Helpers [Internal]
//-------------------------------------------------------------------------
// - DataTypeGetInfo()
// - DataTypeFormatString()
// - DataTypeApplyOp()
// - DataTypeApplyOpFromText()
// - DataTypeCompare()
// - DataTypeClamp()
// - GetMinimumStepAtDecimalPrecision
// - RoundScalarWithFormat<>()
//-------------------------------------------------------------------------

static const SegaUiDataTypeInfo GDataTypeInfo[] =
{
    { sizeof(char),             "S8",   "%d",   "%d"    },  // SegaUiDataType_S8
    { sizeof(unsigned char),    "U8",   "%u",   "%u"    },
    { sizeof(short),            "S16",  "%d",   "%d"    },  // SegaUiDataType_S16
    { sizeof(unsigned short),   "U16",  "%u",   "%u"    },
    { sizeof(int),              "S32",  "%d",   "%d"    },  // SegaUiDataType_S32
    { sizeof(unsigned int),     "U32",  "%u",   "%u"    },
#ifdef _MSC_VER
    { sizeof(ImS64),            "S64",  "%I64d","%I64d" },  // SegaUiDataType_S64
    { sizeof(ImU64),            "U64",  "%I64u","%I64u" },
#else
    { sizeof(ImS64),            "S64",  "%lld", "%lld"  },  // SegaUiDataType_S64
    { sizeof(ImU64),            "U64",  "%llu", "%llu"  },
#endif
    { sizeof(float),            "float", "%.3f","%f"    },  // SegaUiDataType_Float (float are promoted to double in va_arg)
    { sizeof(double),           "double","%f",  "%lf"   },  // SegaUiDataType_Double
};
IM_STATIC_ASSERT(IM_ARRAYSIZE(GDataTypeInfo) == SegaUiDataType_COUNT);

const SegaUiDataTypeInfo* SegaUi::DataTypeGetInfo(SegaUiDataType data_type)
{
    IM_ASSERT(data_type >= 0 && data_type < SegaUiDataType_COUNT);
    return &GDataTypeInfo[data_type];
}

int SegaUi::DataTypeFormatString(char* buf, int buf_size, SegaUiDataType data_type, const void* p_data, const char* format)
{
    // Signedness doesn't matter when pushing integer arguments
    if (data_type == SegaUiDataType_S32 || data_type == SegaUiDataType_U32)
        return ImFormatString(buf, buf_size, format, *(const ImU32*)p_data);
    if (data_type == SegaUiDataType_S64 || data_type == SegaUiDataType_U64)
        return ImFormatString(buf, buf_size, format, *(const ImU64*)p_data);
    if (data_type == SegaUiDataType_Float)
        return ImFormatString(buf, buf_size, format, *(const float*)p_data);
    if (data_type == SegaUiDataType_Double)
        return ImFormatString(buf, buf_size, format, *(const double*)p_data);
    if (data_type == SegaUiDataType_S8)
        return ImFormatString(buf, buf_size, format, *(const ImS8*)p_data);
    if (data_type == SegaUiDataType_U8)
        return ImFormatString(buf, buf_size, format, *(const ImU8*)p_data);
    if (data_type == SegaUiDataType_S16)
        return ImFormatString(buf, buf_size, format, *(const ImS16*)p_data);
    if (data_type == SegaUiDataType_U16)
        return ImFormatString(buf, buf_size, format, *(const ImU16*)p_data);
    IM_ASSERT(0);
    return 0;
}

void SegaUi::DataTypeApplyOp(SegaUiDataType data_type, int op, void* output, const void* arg1, const void* arg2)
{
    IM_ASSERT(op == '+' || op == '-');
    switch (data_type)
    {
        case SegaUiDataType_S8:
            if (op == '+') { *(ImS8*)output  = ImAddClampOverflow(*(const ImS8*)arg1,  *(const ImS8*)arg2,  IM_S8_MIN,  IM_S8_MAX); }
            if (op == '-') { *(ImS8*)output  = ImSubClampOverflow(*(const ImS8*)arg1,  *(const ImS8*)arg2,  IM_S8_MIN,  IM_S8_MAX); }
            return;
        case SegaUiDataType_U8:
            if (op == '+') { *(ImU8*)output  = ImAddClampOverflow(*(const ImU8*)arg1,  *(const ImU8*)arg2,  IM_U8_MIN,  IM_U8_MAX); }
            if (op == '-') { *(ImU8*)output  = ImSubClampOverflow(*(const ImU8*)arg1,  *(const ImU8*)arg2,  IM_U8_MIN,  IM_U8_MAX); }
            return;
        case SegaUiDataType_S16:
            if (op == '+') { *(ImS16*)output = ImAddClampOverflow(*(const ImS16*)arg1, *(const ImS16*)arg2, IM_S16_MIN, IM_S16_MAX); }
            if (op == '-') { *(ImS16*)output = ImSubClampOverflow(*(const ImS16*)arg1, *(const ImS16*)arg2, IM_S16_MIN, IM_S16_MAX); }
            return;
        case SegaUiDataType_U16:
            if (op == '+') { *(ImU16*)output = ImAddClampOverflow(*(const ImU16*)arg1, *(const ImU16*)arg2, IM_U16_MIN, IM_U16_MAX); }
            if (op == '-') { *(ImU16*)output = ImSubClampOverflow(*(const ImU16*)arg1, *(const ImU16*)arg2, IM_U16_MIN, IM_U16_MAX); }
            return;
        case SegaUiDataType_S32:
            if (op == '+') { *(ImS32*)output = ImAddClampOverflow(*(const ImS32*)arg1, *(const ImS32*)arg2, IM_S32_MIN, IM_S32_MAX); }
            if (op == '-') { *(ImS32*)output = ImSubClampOverflow(*(const ImS32*)arg1, *(const ImS32*)arg2, IM_S32_MIN, IM_S32_MAX); }
            return;
        case SegaUiDataType_U32:
            if (op == '+') { *(ImU32*)output = ImAddClampOverflow(*(const ImU32*)arg1, *(const ImU32*)arg2, IM_U32_MIN, IM_U32_MAX); }
            if (op == '-') { *(ImU32*)output = ImSubClampOverflow(*(const ImU32*)arg1, *(const ImU32*)arg2, IM_U32_MIN, IM_U32_MAX); }
            return;
        case SegaUiDataType_S64:
            if (op == '+') { *(ImS64*)output = ImAddClampOverflow(*(const ImS64*)arg1, *(const ImS64*)arg2, IM_S64_MIN, IM_S64_MAX); }
            if (op == '-') { *(ImS64*)output = ImSubClampOverflow(*(const ImS64*)arg1, *(const ImS64*)arg2, IM_S64_MIN, IM_S64_MAX); }
            return;
        case SegaUiDataType_U64:
            if (op == '+') { *(ImU64*)output = ImAddClampOverflow(*(const ImU64*)arg1, *(const ImU64*)arg2, IM_U64_MIN, IM_U64_MAX); }
            if (op == '-') { *(ImU64*)output = ImSubClampOverflow(*(const ImU64*)arg1, *(const ImU64*)arg2, IM_U64_MIN, IM_U64_MAX); }
            return;
        case SegaUiDataType_Float:
            if (op == '+') { *(float*)output = *(const float*)arg1 + *(const float*)arg2; }
            if (op == '-') { *(float*)output = *(const float*)arg1 - *(const float*)arg2; }
            return;
        case SegaUiDataType_Double:
            if (op == '+') { *(double*)output = *(const double*)arg1 + *(const double*)arg2; }
            if (op == '-') { *(double*)output = *(const double*)arg1 - *(const double*)arg2; }
            return;
        case SegaUiDataType_COUNT: break;
    }
    IM_ASSERT(0);
}

// User can input math operators (e.g. +100) to edit a numerical values.
// NB: This is _not_ a full expression evaluator. We should probably add one and replace this dumb mess..
bool SegaUi::DataTypeApplyFromText(const char* buf, SegaUiDataType data_type, void* p_data, const char* format)
{
    while (ImCharIsBlankA(*buf))
        buf++;
    if (!buf[0])
        return false;

    // Copy the value in an opaque buffer so we can compare at the end of the function if it changed at all.
    const SegaUiDataTypeInfo* type_info = DataTypeGetInfo(data_type);
    SegaUiDataTypeTempStorage data_backup;
    memcpy(&data_backup, p_data, type_info->Size);

    // Sanitize format
    // - For float/double we have to ignore format with precision (e.g. "%.2f") because sscanf doesn't take them in, so force them into %f and %lf
    // - In theory could treat empty format as using default, but this would only cover rare/bizarre case of using InputScalar() + integer + format string without %.
    char format_sanitized[32];
    if (data_type == SegaUiDataType_Float || data_type == SegaUiDataType_Double)
        format = type_info->ScanFmt;
    else
        format = ImParseFormatSanitizeForScanning(format, format_sanitized, IM_ARRAYSIZE(format_sanitized));

    // Small types need a 32-bit buffer to receive the result from scanf()
    int v32 = 0;
    if (sscanf(buf, format, type_info->Size >= 4 ? p_data : &v32) < 1)
        return false;
    if (type_info->Size < 4)
    {
        if (data_type == SegaUiDataType_S8)
            *(ImS8*)p_data = (ImS8)ImClamp(v32, (int)IM_S8_MIN, (int)IM_S8_MAX);
        else if (data_type == SegaUiDataType_U8)
            *(ImU8*)p_data = (ImU8)ImClamp(v32, (int)IM_U8_MIN, (int)IM_U8_MAX);
        else if (data_type == SegaUiDataType_S16)
            *(ImS16*)p_data = (ImS16)ImClamp(v32, (int)IM_S16_MIN, (int)IM_S16_MAX);
        else if (data_type == SegaUiDataType_U16)
            *(ImU16*)p_data = (ImU16)ImClamp(v32, (int)IM_U16_MIN, (int)IM_U16_MAX);
        else
            IM_ASSERT(0);
    }

    return memcmp(&data_backup, p_data, type_info->Size) != 0;
}

template<typename T>
static int DataTypeCompareT(const T* lhs, const T* rhs)
{
    if (*lhs < *rhs) return -1;
    if (*lhs > *rhs) return +1;
    return 0;
}

int SegaUi::DataTypeCompare(SegaUiDataType data_type, const void* arg_1, const void* arg_2)
{
    switch (data_type)
    {
    case SegaUiDataType_S8:     return DataTypeCompareT<ImS8  >((const ImS8*  )arg_1, (const ImS8*  )arg_2);
    case SegaUiDataType_U8:     return DataTypeCompareT<ImU8  >((const ImU8*  )arg_1, (const ImU8*  )arg_2);
    case SegaUiDataType_S16:    return DataTypeCompareT<ImS16 >((const ImS16* )arg_1, (const ImS16* )arg_2);
    case SegaUiDataType_U16:    return DataTypeCompareT<ImU16 >((const ImU16* )arg_1, (const ImU16* )arg_2);
    case SegaUiDataType_S32:    return DataTypeCompareT<ImS32 >((const ImS32* )arg_1, (const ImS32* )arg_2);
    case SegaUiDataType_U32:    return DataTypeCompareT<ImU32 >((const ImU32* )arg_1, (const ImU32* )arg_2);
    case SegaUiDataType_S64:    return DataTypeCompareT<ImS64 >((const ImS64* )arg_1, (const ImS64* )arg_2);
    case SegaUiDataType_U64:    return DataTypeCompareT<ImU64 >((const ImU64* )arg_1, (const ImU64* )arg_2);
    case SegaUiDataType_Float:  return DataTypeCompareT<float >((const float* )arg_1, (const float* )arg_2);
    case SegaUiDataType_Double: return DataTypeCompareT<double>((const double*)arg_1, (const double*)arg_2);
    case SegaUiDataType_COUNT:  break;
    }
    IM_ASSERT(0);
    return 0;
}

template<typename T>
static bool DataTypeClampT(T* v, const T* v_min, const T* v_max)
{
    // Clamp, both sides are optional, return true if modified
    if (v_min && *v < *v_min) { *v = *v_min; return true; }
    if (v_max && *v > *v_max) { *v = *v_max; return true; }
    return false;
}

bool SegaUi::DataTypeClamp(SegaUiDataType data_type, void* p_data, const void* p_min, const void* p_max)
{
    switch (data_type)
    {
    case SegaUiDataType_S8:     return DataTypeClampT<ImS8  >((ImS8*  )p_data, (const ImS8*  )p_min, (const ImS8*  )p_max);
    case SegaUiDataType_U8:     return DataTypeClampT<ImU8  >((ImU8*  )p_data, (const ImU8*  )p_min, (const ImU8*  )p_max);
    case SegaUiDataType_S16:    return DataTypeClampT<ImS16 >((ImS16* )p_data, (const ImS16* )p_min, (const ImS16* )p_max);
    case SegaUiDataType_U16:    return DataTypeClampT<ImU16 >((ImU16* )p_data, (const ImU16* )p_min, (const ImU16* )p_max);
    case SegaUiDataType_S32:    return DataTypeClampT<ImS32 >((ImS32* )p_data, (const ImS32* )p_min, (const ImS32* )p_max);
    case SegaUiDataType_U32:    return DataTypeClampT<ImU32 >((ImU32* )p_data, (const ImU32* )p_min, (const ImU32* )p_max);
    case SegaUiDataType_S64:    return DataTypeClampT<ImS64 >((ImS64* )p_data, (const ImS64* )p_min, (const ImS64* )p_max);
    case SegaUiDataType_U64:    return DataTypeClampT<ImU64 >((ImU64* )p_data, (const ImU64* )p_min, (const ImU64* )p_max);
    case SegaUiDataType_Float:  return DataTypeClampT<float >((float* )p_data, (const float* )p_min, (const float* )p_max);
    case SegaUiDataType_Double: return DataTypeClampT<double>((double*)p_data, (const double*)p_min, (const double*)p_max);
    case SegaUiDataType_COUNT:  break;
    }
    IM_ASSERT(0);
    return false;
}

static float GetMinimumStepAtDecimalPrecision(int decimal_precision)
{
    static const float min_steps[10] = { 1.0f, 0.1f, 0.01f, 0.001f, 0.0001f, 0.00001f, 0.000001f, 0.0000001f, 0.00000001f, 0.000000001f };
    if (decimal_precision < 0)
        return FLT_MIN;
    return (decimal_precision < IM_ARRAYSIZE(min_steps)) ? min_steps[decimal_precision] : ImPow(10.0f, (float)-decimal_precision);
}

template<typename TYPE>
TYPE SegaUi::RoundScalarWithFormatT(const char* format, SegaUiDataType data_type, TYPE v)
{
    IM_UNUSED(data_type);
    IM_ASSERT(data_type == SegaUiDataType_Float || data_type == SegaUiDataType_Double);
    const char* fmt_start = ImParseFormatFindStart(format);
    if (fmt_start[0] != '%' || fmt_start[1] == '%') // Don't apply if the value is not visible in the format string
        return v;

    // Sanitize format
    char fmt_sanitized[32];
    ImParseFormatSanitizeForPrinting(fmt_start, fmt_sanitized, IM_ARRAYSIZE(fmt_sanitized));
    fmt_start = fmt_sanitized;

    // Format value with our rounding, and read back
    char v_str[64];
    ImFormatString(v_str, IM_ARRAYSIZE(v_str), fmt_start, v);
    const char* p = v_str;
    while (*p == ' ')
        p++;
    v = (TYPE)ImAtof(p);

    return v;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: DragScalar, DragFloat, DragInt, etc.
//-------------------------------------------------------------------------
// - DragBehaviorT<>() [Internal]
// - DragBehavior() [Internal]
// - DragScalar()
// - DragScalarN()
// - DragFloat()
// - DragFloat2()
// - DragFloat3()
// - DragFloat4()
// - DragFloatRange2()
// - DragInt()
// - DragInt2()
// - DragInt3()
// - DragInt4()
// - DragIntRange2()
//-------------------------------------------------------------------------

// This is called by DragBehavior() when the widget is active (held by mouse or being manipulated with Nav controls)
template<typename TYPE, typename SIGNEDTYPE, typename FLOATTYPE>
bool SegaUi::DragBehaviorT(SegaUiDataType data_type, TYPE* v, float v_speed, const TYPE v_min, const TYPE v_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    const SegaUiAxis axis = (flags & SegaUiSliderFlags_Vertical) ? SegaUiAxis_Y : SegaUiAxis_X;
    const bool is_clamped = (v_min < v_max);
    const bool is_logarithmic = (flags & SegaUiSliderFlags_Logarithmic) != 0;
    const bool is_floating_point = (data_type == SegaUiDataType_Float) || (data_type == SegaUiDataType_Double);

    // Default tweak speed
    if (v_speed == 0.0f && is_clamped && (v_max - v_min < FLT_MAX))
        v_speed = (float)((v_max - v_min) * g.DragSpeedDefaultRatio);

    // Inputs accumulates into g.DragCurrentAccum, which is flushed into the current value as soon as it makes a difference with our precision settings
    float adjust_delta = 0.0f;
    if (g.ActiveIdSource == SegaUiInputSource_Mouse && IsMousePosValid() && IsMouseDragPastThreshold(0, g.IO.MouseDragThreshold * DRAG_MOUSE_THRESHOLD_FACTOR))
    {
        adjust_delta = g.IO.MouseDelta[axis];
        if (g.IO.KeyAlt)
            adjust_delta *= 1.0f / 100.0f;
        if (g.IO.KeyShift)
            adjust_delta *= 10.0f;
    }
    else if (g.ActiveIdSource == SegaUiInputSource_Keyboard || g.ActiveIdSource == SegaUiInputSource_Gamepad)
    {
        const int decimal_precision = is_floating_point ? ImParseFormatPrecision(format, 3) : 0;
        const bool tweak_slow = IsKeyDown((g.NavInputSource == SegaUiInputSource_Gamepad) ? SegaUiKey_NavGamepadTweakSlow : SegaUiKey_NavKeyboardTweakSlow);
        const bool tweak_fast = IsKeyDown((g.NavInputSource == SegaUiInputSource_Gamepad) ? SegaUiKey_NavGamepadTweakFast : SegaUiKey_NavKeyboardTweakFast);
        const float tweak_factor = tweak_slow ? 1.0f / 1.0f : tweak_fast ? 10.0f : 1.0f;
        adjust_delta = GetNavTweakPressedAmount(axis) * tweak_factor;
        v_speed = ImMax(v_speed, GetMinimumStepAtDecimalPrecision(decimal_precision));
    }
    adjust_delta *= v_speed;

    // For vertical drag we currently assume that Up=higher value (like we do with vertical sliders). This may become a parameter.
    if (axis == SegaUiAxis_Y)
        adjust_delta = -adjust_delta;

    // For logarithmic use our range is effectively 0..1 so scale the delta into that range
    if (is_logarithmic && (v_max - v_min < FLT_MAX) && ((v_max - v_min) > 0.000001f)) // Epsilon to avoid /0
        adjust_delta /= (float)(v_max - v_min);

    // Clear current value on activation
    // Avoid altering values and clamping when we are _already_ past the limits and heading in the same direction, so e.g. if range is 0..255, current value is 300 and we are pushing to the right side, keep the 300.
    bool is_just_activated = g.ActiveIdIsJustActivated;
    bool is_already_past_limits_and_pushing_outward = is_clamped && ((*v >= v_max && adjust_delta > 0.0f) || (*v <= v_min && adjust_delta < 0.0f));
    if (is_just_activated || is_already_past_limits_and_pushing_outward)
    {
        g.DragCurrentAccum = 0.0f;
        g.DragCurrentAccumDirty = false;
    }
    else if (adjust_delta != 0.0f)
    {
        g.DragCurrentAccum += adjust_delta;
        g.DragCurrentAccumDirty = true;
    }

    if (!g.DragCurrentAccumDirty)
        return false;

    TYPE v_cur = *v;
    FLOATTYPE v_old_ref_for_accum_remainder = (FLOATTYPE)0.0f;

    float logarithmic_zero_epsilon = 0.0f; // Only valid when is_logarithmic is true
    const float zero_deadzone_halfsize = 0.0f; // Drag widgets have no deadzone (as it doesn't make sense)
    if (is_logarithmic)
    {
        // When using logarithmic sliders, we need to clamp to avoid hitting zero, but our choice of clamp value greatly affects slider precision. We attempt to use the specified precision to estimate a good lower bound.
        const int decimal_precision = is_floating_point ? ImParseFormatPrecision(format, 3) : 1;
        logarithmic_zero_epsilon = ImPow(0.1f, (float)decimal_precision);

        // Convert to parametric space, apply delta, convert back
        float v_old_parametric = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, v_cur, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
        float v_new_parametric = v_old_parametric + g.DragCurrentAccum;
        v_cur = ScaleValueFromRatioT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, v_new_parametric, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
        v_old_ref_for_accum_remainder = v_old_parametric;
    }
    else
    {
        v_cur += (SIGNEDTYPE)g.DragCurrentAccum;
    }

    // Round to user desired precision based on format string
    if (is_floating_point && !(flags & SegaUiSliderFlags_NoRoundToFormat))
        v_cur = RoundScalarWithFormatT<TYPE>(format, data_type, v_cur);

    // Preserve remainder after rounding has been applied. This also allow slow tweaking of values.
    g.DragCurrentAccumDirty = false;
    if (is_logarithmic)
    {
        // Convert to parametric space, apply delta, convert back
        float v_new_parametric = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, v_cur, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
        g.DragCurrentAccum -= (float)(v_new_parametric - v_old_ref_for_accum_remainder);
    }
    else
    {
        g.DragCurrentAccum -= (float)((SIGNEDTYPE)v_cur - (SIGNEDTYPE)*v);
    }

    // Lose zero sign for float/double
    if (v_cur == (TYPE)-0)
        v_cur = (TYPE)0;

    // Clamp values (+ handle overflow/wrap-around for integer types)
    if (*v != v_cur && is_clamped)
    {
        if (v_cur < v_min || (v_cur > *v && adjust_delta < 0.0f && !is_floating_point))
            v_cur = v_min;
        if (v_cur > v_max || (v_cur < *v && adjust_delta > 0.0f && !is_floating_point))
            v_cur = v_max;
    }

    // Apply result
    if (*v == v_cur)
        return false;
    *v = v_cur;
    return true;
}

bool SegaUi::DragBehavior(SegaUiID id, SegaUiDataType data_type, void* p_v, float v_speed, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags)
{
    // Read imgui.cpp "API BREAKING CHANGES" section for 1.78 if you hit this assert.
    IM_ASSERT((flags == 1 || (flags & SegaUiSliderFlags_InvalidMask_) == 0) && "Invalid SegaUiSliderFlags flags! Has the 'float power' argument been mistakenly cast to flags? Call function with SegaUiSliderFlags_Logarithmic flags instead.");

    SegaUiContext& g = *GSegaUi;
    if (g.ActiveId == id)
    {
        // Those are the things we can do easily outside the DragBehaviorT<> template, saves code generation.
        if (g.ActiveIdSource == SegaUiInputSource_Mouse && !g.IO.MouseDown[0])
            ClearActiveID();
        else if ((g.ActiveIdSource == SegaUiInputSource_Keyboard || g.ActiveIdSource == SegaUiInputSource_Gamepad) && g.NavActivatePressedId == id && !g.ActiveIdIsJustActivated)
            ClearActiveID();
    }
    if (g.ActiveId != id)
        return false;
    if ((g.LastItemData.InFlags & SegaUiItemFlags_ReadOnly) || (flags & SegaUiSliderFlags_ReadOnly))
        return false;

    switch (data_type)
    {
    case SegaUiDataType_S8:     { ImS32 v32 = (ImS32)*(ImS8*)p_v;  bool r = DragBehaviorT<ImS32, ImS32, float>(SegaUiDataType_S32, &v32, v_speed, p_min ? *(const ImS8*) p_min : IM_S8_MIN,  p_max ? *(const ImS8*)p_max  : IM_S8_MAX,  format, flags); if (r) *(ImS8*)p_v = (ImS8)v32; return r; }
    case SegaUiDataType_U8:     { ImU32 v32 = (ImU32)*(ImU8*)p_v;  bool r = DragBehaviorT<ImU32, ImS32, float>(SegaUiDataType_U32, &v32, v_speed, p_min ? *(const ImU8*) p_min : IM_U8_MIN,  p_max ? *(const ImU8*)p_max  : IM_U8_MAX,  format, flags); if (r) *(ImU8*)p_v = (ImU8)v32; return r; }
    case SegaUiDataType_S16:    { ImS32 v32 = (ImS32)*(ImS16*)p_v; bool r = DragBehaviorT<ImS32, ImS32, float>(SegaUiDataType_S32, &v32, v_speed, p_min ? *(const ImS16*)p_min : IM_S16_MIN, p_max ? *(const ImS16*)p_max : IM_S16_MAX, format, flags); if (r) *(ImS16*)p_v = (ImS16)v32; return r; }
    case SegaUiDataType_U16:    { ImU32 v32 = (ImU32)*(ImU16*)p_v; bool r = DragBehaviorT<ImU32, ImS32, float>(SegaUiDataType_U32, &v32, v_speed, p_min ? *(const ImU16*)p_min : IM_U16_MIN, p_max ? *(const ImU16*)p_max : IM_U16_MAX, format, flags); if (r) *(ImU16*)p_v = (ImU16)v32; return r; }
    case SegaUiDataType_S32:    return DragBehaviorT<ImS32, ImS32, float >(data_type, (ImS32*)p_v,  v_speed, p_min ? *(const ImS32* )p_min : IM_S32_MIN, p_max ? *(const ImS32* )p_max : IM_S32_MAX, format, flags);
    case SegaUiDataType_U32:    return DragBehaviorT<ImU32, ImS32, float >(data_type, (ImU32*)p_v,  v_speed, p_min ? *(const ImU32* )p_min : IM_U32_MIN, p_max ? *(const ImU32* )p_max : IM_U32_MAX, format, flags);
    case SegaUiDataType_S64:    return DragBehaviorT<ImS64, ImS64, double>(data_type, (ImS64*)p_v,  v_speed, p_min ? *(const ImS64* )p_min : IM_S64_MIN, p_max ? *(const ImS64* )p_max : IM_S64_MAX, format, flags);
    case SegaUiDataType_U64:    return DragBehaviorT<ImU64, ImS64, double>(data_type, (ImU64*)p_v,  v_speed, p_min ? *(const ImU64* )p_min : IM_U64_MIN, p_max ? *(const ImU64* )p_max : IM_U64_MAX, format, flags);
    case SegaUiDataType_Float:  return DragBehaviorT<float, float, float >(data_type, (float*)p_v,  v_speed, p_min ? *(const float* )p_min : -FLT_MAX,   p_max ? *(const float* )p_max : FLT_MAX,    format, flags);
    case SegaUiDataType_Double: return DragBehaviorT<double,double,double>(data_type, (double*)p_v, v_speed, p_min ? *(const double*)p_min : -DBL_MAX,   p_max ? *(const double*)p_max : DBL_MAX,    format, flags);
    case SegaUiDataType_COUNT:  break;
    }
    IM_ASSERT(0);
    return false;
}

// Note: p_data, p_min and p_max are _pointers_ to a memory address holding the data. For a Drag widget, p_min and p_max are optional.
// Read code of e.g. DragFloat(), DragInt() etc. or examples in 'Demo->Widgets->Data Types' to understand how to use this function directly.
bool SegaUi::DragScalar(const char* label, SegaUiDataType data_type, void* p_data, float v_speed, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const float w = CalcItemWidth();

    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + ImVec2(w, label_size.y + style.FramePadding.y * 2.0f));
    const ImRect total_bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f, 0.0f));

    const bool temp_input_allowed = (flags & SegaUiSliderFlags_NoInput) == 0;
    ItemSize(total_bb, style.FramePadding.y);
    if (!ItemAdd(total_bb, id, &frame_bb, temp_input_allowed ? SegaUiItemFlags_Inputable : 0))
        return false;

    // Default format string when passing NULL
    if (format == NULL)
        format = DataTypeGetInfo(data_type)->PrintFmt;

    const bool hovered = ItemHoverable(frame_bb, id);
    bool temp_input_is_active = temp_input_allowed && TempInputIsActive(id);
    if (!temp_input_is_active)
    {
        // Tabbing or CTRL-clicking on Drag turns it into an InputText
        const bool input_requested_by_tabbing = temp_input_allowed && (g.LastItemData.StatusFlags & SegaUiItemStatusFlags_FocusedByTabbing) != 0;
        const bool clicked = hovered && IsMouseClicked(0, id);
        const bool double_clicked = (hovered && g.IO.MouseClickedCount[0] == 2 && TestKeyOwner(SegaUiKey_MouseLeft, id));
        const bool make_active = (input_requested_by_tabbing || clicked || double_clicked || g.NavActivateId == id);
        if (make_active && (clicked || double_clicked))
            SetKeyOwner(SegaUiKey_MouseLeft, id);
        if (make_active && temp_input_allowed)
            if (input_requested_by_tabbing || (clicked && g.IO.KeyCtrl) || double_clicked || (g.NavActivateId == id && (g.NavActivateFlags & SegaUiActivateFlags_PreferInput)))
                temp_input_is_active = true;

        // (Optional) simple click (without moving) turns Drag into an InputText
        if (g.IO.ConfigDragClickToInputText && temp_input_allowed && !temp_input_is_active)
            if (g.ActiveId == id && hovered && g.IO.MouseReleased[0] && !IsMouseDragPastThreshold(0, g.IO.MouseDragThreshold * DRAG_MOUSE_THRESHOLD_FACTOR))
            {
                g.NavActivateId = id;
                g.NavActivateFlags = SegaUiActivateFlags_PreferInput;
                temp_input_is_active = true;
            }

        if (make_active && !temp_input_is_active)
        {
            SetActiveID(id, window);
            SetFocusID(id, window);
            FocusWindow(window);
            g.ActiveIdUsingNavDirMask = (1 << SegaUiDir_Left) | (1 << SegaUiDir_Right);
        }
    }

    if (temp_input_is_active)
    {
        // Only clamp CTRL+Click input when SegaUiSliderFlags_AlwaysClamp is set
        const bool is_clamp_input = (flags & SegaUiSliderFlags_AlwaysClamp) != 0 && (p_min == NULL || p_max == NULL || DataTypeCompare(data_type, p_min, p_max) < 0);
        return TempInputScalar(frame_bb, id, label, data_type, p_data, format, is_clamp_input ? p_min : NULL, is_clamp_input ? p_max : NULL);
    }

    // Draw frame
    const ImU32 frame_col = GetColorU32(g.ActiveId == id ? SegaUiCol_FrameBgActive : hovered ? SegaUiCol_FrameBgHovered : SegaUiCol_FrameBg);
    RenderNavHighlight(frame_bb, id);
    RenderFrame(frame_bb.Min, frame_bb.Max, frame_col, true, style.FrameRounding);

    // Drag behavior
    const bool value_changed = DragBehavior(id, data_type, p_data, v_speed, p_min, p_max, format, flags);
    if (value_changed)
        MarkItemEdited(id);

    // Display value using user-provided display format so user can add prefix/suffix/decorations to the value.
    char value_buf[64];
    const char* value_buf_end = value_buf + DataTypeFormatString(value_buf, IM_ARRAYSIZE(value_buf), data_type, p_data, format);
    if (g.LogEnabled)
        LogSetNextTextDecoration("{", "}");
    RenderTextClipped(frame_bb.Min, frame_bb.Max, value_buf, value_buf_end, NULL, ImVec2(0.5f, 0.5f));

    if (label_size.x > 0.0f)
        RenderText(ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x, frame_bb.Min.y + style.FramePadding.y), label);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags | (temp_input_allowed ? SegaUiItemStatusFlags_Inputable : 0));
    return value_changed;
}

bool SegaUi::DragScalarN(const char* label, SegaUiDataType data_type, void* p_data, int components, float v_speed, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    bool value_changed = false;
    BeginGroup();
    PushID(label);
    PushMultiItemsWidths(components, CalcItemWidth());
    size_t type_size = GDataTypeInfo[data_type].Size;
    for (int i = 0; i < components; i++)
    {
        PushID(i);
        if (i > 0)
            SameLine(0, g.Style.ItemInnerSpacing.x);
        value_changed |= DragScalar("", data_type, p_data, v_speed, p_min, p_max, format, flags);
        PopID();
        PopItemWidth();
        p_data = (void*)((char*)p_data + type_size);
    }
    PopID();

    const char* label_end = FindRenderedTextEnd(label);
    if (label != label_end)
    {
        SameLine(0, g.Style.ItemInnerSpacing.x);
        TextEx(label, label_end);
    }

    EndGroup();
    return value_changed;
}

bool SegaUi::DragFloat(const char* label, float* v, float v_speed, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalar(label, SegaUiDataType_Float, v, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragFloat2(const char* label, float v[2], float v_speed, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_Float, v, 2, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragFloat3(const char* label, float v[3], float v_speed, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_Float, v, 3, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragFloat4(const char* label, float v[4], float v_speed, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_Float, v, 4, v_speed, &v_min, &v_max, format, flags);
}

// NB: You likely want to specify the SegaUiSliderFlags_AlwaysClamp when using this.
bool SegaUi::DragFloatRange2(const char* label, float* v_current_min, float* v_current_max, float v_speed, float v_min, float v_max, const char* format, const char* format_max, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    PushID(label);
    BeginGroup();
    PushMultiItemsWidths(2, CalcItemWidth());

    float min_min = (v_min >= v_max) ? -FLT_MAX : v_min;
    float min_max = (v_min >= v_max) ? *v_current_max : ImMin(v_max, *v_current_max);
    SegaUiSliderFlags min_flags = flags | ((min_min == min_max) ? SegaUiSliderFlags_ReadOnly : 0);
    bool value_changed = DragScalar("##min", SegaUiDataType_Float, v_current_min, v_speed, &min_min, &min_max, format, min_flags);
    PopItemWidth();
    SameLine(0, g.Style.ItemInnerSpacing.x);

    float max_min = (v_min >= v_max) ? *v_current_min : ImMax(v_min, *v_current_min);
    float max_max = (v_min >= v_max) ? FLT_MAX : v_max;
    SegaUiSliderFlags max_flags = flags | ((max_min == max_max) ? SegaUiSliderFlags_ReadOnly : 0);
    value_changed |= DragScalar("##max", SegaUiDataType_Float, v_current_max, v_speed, &max_min, &max_max, format_max ? format_max : format, max_flags);
    PopItemWidth();
    SameLine(0, g.Style.ItemInnerSpacing.x);

    TextEx(label, FindRenderedTextEnd(label));
    EndGroup();
    PopID();

    return value_changed;
}

// NB: v_speed is float to allow adjusting the drag speed with more precision
bool SegaUi::DragInt(const char* label, int* v, float v_speed, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalar(label, SegaUiDataType_S32, v, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragInt2(const char* label, int v[2], float v_speed, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_S32, v, 2, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragInt3(const char* label, int v[3], float v_speed, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_S32, v, 3, v_speed, &v_min, &v_max, format, flags);
}

bool SegaUi::DragInt4(const char* label, int v[4], float v_speed, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return DragScalarN(label, SegaUiDataType_S32, v, 4, v_speed, &v_min, &v_max, format, flags);
}

// NB: You likely want to specify the SegaUiSliderFlags_AlwaysClamp when using this.
bool SegaUi::DragIntRange2(const char* label, int* v_current_min, int* v_current_max, float v_speed, int v_min, int v_max, const char* format, const char* format_max, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    PushID(label);
    BeginGroup();
    PushMultiItemsWidths(2, CalcItemWidth());

    int min_min = (v_min >= v_max) ? INT_MIN : v_min;
    int min_max = (v_min >= v_max) ? *v_current_max : ImMin(v_max, *v_current_max);
    SegaUiSliderFlags min_flags = flags | ((min_min == min_max) ? SegaUiSliderFlags_ReadOnly : 0);
    bool value_changed = DragInt("##min", v_current_min, v_speed, min_min, min_max, format, min_flags);
    PopItemWidth();
    SameLine(0, g.Style.ItemInnerSpacing.x);

    int max_min = (v_min >= v_max) ? *v_current_min : ImMax(v_min, *v_current_min);
    int max_max = (v_min >= v_max) ? INT_MAX : v_max;
    SegaUiSliderFlags max_flags = flags | ((max_min == max_max) ? SegaUiSliderFlags_ReadOnly : 0);
    value_changed |= DragInt("##max", v_current_max, v_speed, max_min, max_max, format_max ? format_max : format, max_flags);
    PopItemWidth();
    SameLine(0, g.Style.ItemInnerSpacing.x);

    TextEx(label, FindRenderedTextEnd(label));
    EndGroup();
    PopID();

    return value_changed;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: SliderScalar, SliderFloat, SliderInt, etc.
//-------------------------------------------------------------------------
// - ScaleRatioFromValueT<> [Internal]
// - ScaleValueFromRatioT<> [Internal]
// - SliderBehaviorT<>() [Internal]
// - SliderBehavior() [Internal]
// - SliderScalar()
// - SliderScalarN()
// - SliderFloat()
// - SliderFloat2()
// - SliderFloat3()
// - SliderFloat4()
// - SliderAngle()
// - SliderInt()
// - SliderInt2()
// - SliderInt3()
// - SliderInt4()
// - VSliderScalar()
// - VSliderFloat()
// - VSliderInt()
//-------------------------------------------------------------------------

// Convert a value v in the output space of a slider into a parametric position on the slider itself (the logical opposite of ScaleValueFromRatioT)
template<typename TYPE, typename SIGNEDTYPE, typename FLOATTYPE>
float SegaUi::ScaleRatioFromValueT(SegaUiDataType data_type, TYPE v, TYPE v_min, TYPE v_max, bool is_logarithmic, float logarithmic_zero_epsilon, float zero_deadzone_halfsize)
{
    if (v_min == v_max)
        return 0.0f;
    IM_UNUSED(data_type);

    const TYPE v_clamped = (v_min < v_max) ? ImClamp(v, v_min, v_max) : ImClamp(v, v_max, v_min);
    if (is_logarithmic)
    {
        bool flipped = v_max < v_min;

        if (flipped) // Handle the case where the range is backwards
            ImSwap(v_min, v_max);

        // Fudge min/max to avoid getting close to log(0)
        FLOATTYPE v_min_fudged = (ImAbs((FLOATTYPE)v_min) < logarithmic_zero_epsilon) ? ((v_min < 0.0f) ? -logarithmic_zero_epsilon : logarithmic_zero_epsilon) : (FLOATTYPE)v_min;
        FLOATTYPE v_max_fudged = (ImAbs((FLOATTYPE)v_max) < logarithmic_zero_epsilon) ? ((v_max < 0.0f) ? -logarithmic_zero_epsilon : logarithmic_zero_epsilon) : (FLOATTYPE)v_max;

        // Awkward special cases - we need ranges of the form (-100 .. 0) to convert to (-100 .. -epsilon), not (-100 .. epsilon)
        if ((v_min == 0.0f) && (v_max < 0.0f))
            v_min_fudged = -logarithmic_zero_epsilon;
        else if ((v_max == 0.0f) && (v_min < 0.0f))
            v_max_fudged = -logarithmic_zero_epsilon;

        float result;
        if (v_clamped <= v_min_fudged)
            result = 0.0f; // Workaround for values that are in-range but below our fudge
        else if (v_clamped >= v_max_fudged)
            result = 1.0f; // Workaround for values that are in-range but above our fudge
        else if ((v_min * v_max) < 0.0f) // Range crosses zero, so split into two portions
        {
            float zero_point_center = (-(float)v_min) / ((float)v_max - (float)v_min); // The zero point in parametric space.  There's an argument we should take the logarithmic nature into account when calculating this, but for now this should do (and the most common case of a symmetrical range works fine)
            float zero_point_snap_L = zero_point_center - zero_deadzone_halfsize;
            float zero_point_snap_R = zero_point_center + zero_deadzone_halfsize;
            if (v == 0.0f)
                result = zero_point_center; // Special case for exactly zero
            else if (v < 0.0f)
                result = (1.0f - (float)(ImLog(-(FLOATTYPE)v_clamped / logarithmic_zero_epsilon) / ImLog(-v_min_fudged / logarithmic_zero_epsilon))) * zero_point_snap_L;
            else
                result = zero_point_snap_R + ((float)(ImLog((FLOATTYPE)v_clamped / logarithmic_zero_epsilon) / ImLog(v_max_fudged / logarithmic_zero_epsilon)) * (1.0f - zero_point_snap_R));
        }
        else if ((v_min < 0.0f) || (v_max < 0.0f)) // Entirely negative slider
            result = 1.0f - (float)(ImLog(-(FLOATTYPE)v_clamped / -v_max_fudged) / ImLog(-v_min_fudged / -v_max_fudged));
        else
            result = (float)(ImLog((FLOATTYPE)v_clamped / v_min_fudged) / ImLog(v_max_fudged / v_min_fudged));

        return flipped ? (1.0f - result) : result;
    }
    else
    {
        // Linear slider
        return (float)((FLOATTYPE)(SIGNEDTYPE)(v_clamped - v_min) / (FLOATTYPE)(SIGNEDTYPE)(v_max - v_min));
    }
}

// Convert a parametric position on a slider into a value v in the output space (the logical opposite of ScaleRatioFromValueT)
template<typename TYPE, typename SIGNEDTYPE, typename FLOATTYPE>
TYPE SegaUi::ScaleValueFromRatioT(SegaUiDataType data_type, float t, TYPE v_min, TYPE v_max, bool is_logarithmic, float logarithmic_zero_epsilon, float zero_deadzone_halfsize)
{
    // We special-case the extents because otherwise our logarithmic fudging can lead to "mathematically correct"
    // but non-intuitive behaviors like a fully-left slider not actually reaching the minimum value. Also generally simpler.
    if (t <= 0.0f || v_min == v_max)
        return v_min;
    if (t >= 1.0f)
        return v_max;

    TYPE result = (TYPE)0;
    if (is_logarithmic)
    {
        // Fudge min/max to avoid getting silly results close to zero
        FLOATTYPE v_min_fudged = (ImAbs((FLOATTYPE)v_min) < logarithmic_zero_epsilon) ? ((v_min < 0.0f) ? -logarithmic_zero_epsilon : logarithmic_zero_epsilon) : (FLOATTYPE)v_min;
        FLOATTYPE v_max_fudged = (ImAbs((FLOATTYPE)v_max) < logarithmic_zero_epsilon) ? ((v_max < 0.0f) ? -logarithmic_zero_epsilon : logarithmic_zero_epsilon) : (FLOATTYPE)v_max;

        const bool flipped = v_max < v_min; // Check if range is "backwards"
        if (flipped)
            ImSwap(v_min_fudged, v_max_fudged);

        // Awkward special case - we need ranges of the form (-100 .. 0) to convert to (-100 .. -epsilon), not (-100 .. epsilon)
        if ((v_max == 0.0f) && (v_min < 0.0f))
            v_max_fudged = -logarithmic_zero_epsilon;

        float t_with_flip = flipped ? (1.0f - t) : t; // t, but flipped if necessary to account for us flipping the range

        if ((v_min * v_max) < 0.0f) // Range crosses zero, so we have to do this in two parts
        {
            float zero_point_center = (-(float)ImMin(v_min, v_max)) / ImAbs((float)v_max - (float)v_min); // The zero point in parametric space
            float zero_point_snap_L = zero_point_center - zero_deadzone_halfsize;
            float zero_point_snap_R = zero_point_center + zero_deadzone_halfsize;
            if (t_with_flip >= zero_point_snap_L && t_with_flip <= zero_point_snap_R)
                result = (TYPE)0.0f; // Special case to make getting exactly zero possible (the epsilon prevents it otherwise)
            else if (t_with_flip < zero_point_center)
                result = (TYPE)-(logarithmic_zero_epsilon * ImPow(-v_min_fudged / logarithmic_zero_epsilon, (FLOATTYPE)(1.0f - (t_with_flip / zero_point_snap_L))));
            else
                result = (TYPE)(logarithmic_zero_epsilon * ImPow(v_max_fudged / logarithmic_zero_epsilon, (FLOATTYPE)((t_with_flip - zero_point_snap_R) / (1.0f - zero_point_snap_R))));
        }
        else if ((v_min < 0.0f) || (v_max < 0.0f)) // Entirely negative slider
            result = (TYPE)-(-v_max_fudged * ImPow(-v_min_fudged / -v_max_fudged, (FLOATTYPE)(1.0f - t_with_flip)));
        else
            result = (TYPE)(v_min_fudged * ImPow(v_max_fudged / v_min_fudged, (FLOATTYPE)t_with_flip));
    }
    else
    {
        // Linear slider
        const bool is_floating_point = (data_type == SegaUiDataType_Float) || (data_type == SegaUiDataType_Double);
        if (is_floating_point)
        {
            result = ImLerp(v_min, v_max, t);
        }
        else if (t < 1.0)
        {
            // - For integer values we want the clicking position to match the grab box so we round above
            //   This code is carefully tuned to work with large values (e.g. high ranges of U64) while preserving this property..
            // - Not doing a *1.0 multiply at the end of a range as it tends to be lossy. While absolute aiming at a large s64/u64
            //   range is going to be imprecise anyway, with this check we at least make the edge values matches expected limits.
            FLOATTYPE v_new_off_f = (SIGNEDTYPE)(v_max - v_min) * t;
            result = (TYPE)((SIGNEDTYPE)v_min + (SIGNEDTYPE)(v_new_off_f + (FLOATTYPE)(v_min > v_max ? -0.5 : 0.5)));
        }
    }

    return result;
}

// FIXME: Try to move more of the code into shared SliderBehavior()
template<typename TYPE, typename SIGNEDTYPE, typename FLOATTYPE>
bool SegaUi::SliderBehaviorT(const ImRect& bb, SegaUiID id, SegaUiDataType data_type, TYPE* v, const TYPE v_min, const TYPE v_max, const char* format, SegaUiSliderFlags flags, ImRect* out_grab_bb)
{
    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;

    const SegaUiAxis axis = (flags & SegaUiSliderFlags_Vertical) ? SegaUiAxis_Y : SegaUiAxis_X;
    const bool is_logarithmic = (flags & SegaUiSliderFlags_Logarithmic) != 0;
    const bool is_floating_point = (data_type == SegaUiDataType_Float) || (data_type == SegaUiDataType_Double);
    const SIGNEDTYPE v_range = (v_min < v_max ? v_max - v_min : v_min - v_max);

    // Calculate bounds
    const float grab_padding = 2.0f; // FIXME: Should be part of style.
    const float slider_sz = (bb.Max[axis] - bb.Min[axis]) - grab_padding * 2.0f;
    float grab_sz = style.GrabMinSize;
    if (!is_floating_point && v_range >= 0)                                     // v_range < 0 may happen on integer overflows
        grab_sz = ImMax((float)(slider_sz / (v_range + 1)), style.GrabMinSize); // For integer sliders: if possible have the grab size represent 1 unit
    grab_sz = ImMin(grab_sz, slider_sz);
    const float slider_usable_sz = slider_sz - grab_sz;
    const float slider_usable_pos_min = bb.Min[axis] + grab_padding + grab_sz * 0.5f;
    const float slider_usable_pos_max = bb.Max[axis] - grab_padding - grab_sz * 0.5f;

    float logarithmic_zero_epsilon = 0.0f; // Only valid when is_logarithmic is true
    float zero_deadzone_halfsize = 0.0f; // Only valid when is_logarithmic is true
    if (is_logarithmic)
    {
        // When using logarithmic sliders, we need to clamp to avoid hitting zero, but our choice of clamp value greatly affects slider precision. We attempt to use the specified precision to estimate a good lower bound.
        const int decimal_precision = is_floating_point ? ImParseFormatPrecision(format, 3) : 1;
        logarithmic_zero_epsilon = ImPow(0.1f, (float)decimal_precision);
        zero_deadzone_halfsize = (style.LogSliderDeadzone * 0.5f) / ImMax(slider_usable_sz, 1.0f);
    }

    // Process interacting with the slider
    bool value_changed = false;
    if (g.ActiveId == id)
    {
        bool set_new_value = false;
        float clicked_t = 0.0f;
        if (g.ActiveIdSource == SegaUiInputSource_Mouse)
        {
            if (!g.IO.MouseDown[0])
            {
                ClearActiveID();
            }
            else
            {
                const float mouse_abs_pos = g.IO.MousePos[axis];
                if (g.ActiveIdIsJustActivated)
                {
                    float grab_t = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, *v, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
                    if (axis == SegaUiAxis_Y)
                        grab_t = 1.0f - grab_t;
                    const float grab_pos = ImLerp(slider_usable_pos_min, slider_usable_pos_max, grab_t);
                    const bool clicked_around_grab = (mouse_abs_pos >= grab_pos - grab_sz * 0.5f - 1.0f) && (mouse_abs_pos <= grab_pos + grab_sz * 0.5f + 1.0f); // No harm being extra generous here.
                    g.SliderGrabClickOffset = (clicked_around_grab && is_floating_point) ? mouse_abs_pos - grab_pos : 0.0f;
                }
                if (slider_usable_sz > 0.0f)
                    clicked_t = ImSaturate((mouse_abs_pos - g.SliderGrabClickOffset - slider_usable_pos_min) / slider_usable_sz);
                if (axis == SegaUiAxis_Y)
                    clicked_t = 1.0f - clicked_t;
                set_new_value = true;
            }
        }
        else if (g.ActiveIdSource == SegaUiInputSource_Keyboard || g.ActiveIdSource == SegaUiInputSource_Gamepad)
        {
            if (g.ActiveIdIsJustActivated)
            {
                g.SliderCurrentAccum = 0.0f; // Reset any stored nav delta upon activation
                g.SliderCurrentAccumDirty = false;
            }

            float input_delta = (axis == SegaUiAxis_X) ? GetNavTweakPressedAmount(axis) : -GetNavTweakPressedAmount(axis);
            if (input_delta != 0.0f)
            {
                const bool tweak_slow = IsKeyDown((g.NavInputSource == SegaUiInputSource_Gamepad) ? SegaUiKey_NavGamepadTweakSlow : SegaUiKey_NavKeyboardTweakSlow);
                const bool tweak_fast = IsKeyDown((g.NavInputSource == SegaUiInputSource_Gamepad) ? SegaUiKey_NavGamepadTweakFast : SegaUiKey_NavKeyboardTweakFast);
                const int decimal_precision = is_floating_point ? ImParseFormatPrecision(format, 3) : 0;
                if (decimal_precision > 0)
                {
                    input_delta /= 100.0f;    // Gamepad/keyboard tweak speeds in % of slider bounds
                    if (tweak_slow)
                        input_delta /= 10.0f;
                }
                else
                {
                    if ((v_range >= -100.0f && v_range <= 100.0f) || tweak_slow)
                        input_delta = ((input_delta < 0.0f) ? -1.0f : +1.0f) / (float)v_range; // Gamepad/keyboard tweak speeds in integer steps
                    else
                        input_delta /= 100.0f;
                }
                if (tweak_fast)
                    input_delta *= 10.0f;

                g.SliderCurrentAccum += input_delta;
                g.SliderCurrentAccumDirty = true;
            }

            float delta = g.SliderCurrentAccum;
            if (g.NavActivatePressedId == id && !g.ActiveIdIsJustActivated)
            {
                ClearActiveID();
            }
            else if (g.SliderCurrentAccumDirty)
            {
                clicked_t = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, *v, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);

                if ((clicked_t >= 1.0f && delta > 0.0f) || (clicked_t <= 0.0f && delta < 0.0f)) // This is to avoid applying the saturation when already past the limits
                {
                    set_new_value = false;
                    g.SliderCurrentAccum = 0.0f; // If pushing up against the limits, don't continue to accumulate
                }
                else
                {
                    set_new_value = true;
                    float old_clicked_t = clicked_t;
                    clicked_t = ImSaturate(clicked_t + delta);

                    // Calculate what our "new" clicked_t will be, and thus how far we actually moved the slider, and subtract this from the accumulator
                    TYPE v_new = ScaleValueFromRatioT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, clicked_t, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
                    if (is_floating_point && !(flags & SegaUiSliderFlags_NoRoundToFormat))
                        v_new = RoundScalarWithFormatT<TYPE>(format, data_type, v_new);
                    float new_clicked_t = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, v_new, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);

                    if (delta > 0)
                        g.SliderCurrentAccum -= ImMin(new_clicked_t - old_clicked_t, delta);
                    else
                        g.SliderCurrentAccum -= ImMax(new_clicked_t - old_clicked_t, delta);
                }

                g.SliderCurrentAccumDirty = false;
            }
        }

        if (set_new_value)
        {
            TYPE v_new = ScaleValueFromRatioT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, clicked_t, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);

            // Round to user desired precision based on format string
            if (is_floating_point && !(flags & SegaUiSliderFlags_NoRoundToFormat))
                v_new = RoundScalarWithFormatT<TYPE>(format, data_type, v_new);

            // Apply result
            if (*v != v_new)
            {
                *v = v_new;
                value_changed = true;
            }
        }
    }

    if (slider_sz < 1.0f)
    {
        *out_grab_bb = ImRect(bb.Min, bb.Min);
    }
    else
    {
        // Output grab position so it can be displayed by the caller
        float grab_t = ScaleRatioFromValueT<TYPE, SIGNEDTYPE, FLOATTYPE>(data_type, *v, v_min, v_max, is_logarithmic, logarithmic_zero_epsilon, zero_deadzone_halfsize);
        if (axis == SegaUiAxis_Y)
            grab_t = 1.0f - grab_t;
        const float grab_pos = ImLerp(slider_usable_pos_min, slider_usable_pos_max, grab_t);
        if (axis == SegaUiAxis_X)
            *out_grab_bb = ImRect(grab_pos - grab_sz * 0.5f, bb.Min.y + grab_padding, grab_pos + grab_sz * 0.5f, bb.Max.y - grab_padding);
        else
            *out_grab_bb = ImRect(bb.Min.x + grab_padding, grab_pos - grab_sz * 0.5f, bb.Max.x - grab_padding, grab_pos + grab_sz * 0.5f);
    }

    return value_changed;
}

// For 32-bit and larger types, slider bounds are limited to half the natural type range.
// So e.g. an integer Slider between INT_MAX-10 and INT_MAX will fail, but an integer Slider between INT_MAX/2-10 and INT_MAX/2 will be ok.
// It would be possible to lift that limitation with some work but it doesn't seem to be worth it for sliders.
bool SegaUi::SliderBehavior(const ImRect& bb, SegaUiID id, SegaUiDataType data_type, void* p_v, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags, ImRect* out_grab_bb)
{
    // Read imgui.cpp "API BREAKING CHANGES" section for 1.78 if you hit this assert.
    IM_ASSERT((flags == 1 || (flags & SegaUiSliderFlags_InvalidMask_) == 0) && "Invalid SegaUiSliderFlags flag!  Has the 'float power' argument been mistakenly cast to flags? Call function with SegaUiSliderFlags_Logarithmic flags instead.");

    // Those are the things we can do easily outside the SliderBehaviorT<> template, saves code generation.
    SegaUiContext& g = *GSegaUi;
    if ((g.LastItemData.InFlags & SegaUiItemFlags_ReadOnly) || (flags & SegaUiSliderFlags_ReadOnly))
        return false;

    switch (data_type)
    {
    case SegaUiDataType_S8:  { ImS32 v32 = (ImS32)*(ImS8*)p_v;  bool r = SliderBehaviorT<ImS32, ImS32, float>(bb, id, SegaUiDataType_S32, &v32, *(const ImS8*)p_min,  *(const ImS8*)p_max,  format, flags, out_grab_bb); if (r) *(ImS8*)p_v  = (ImS8)v32;  return r; }
    case SegaUiDataType_U8:  { ImU32 v32 = (ImU32)*(ImU8*)p_v;  bool r = SliderBehaviorT<ImU32, ImS32, float>(bb, id, SegaUiDataType_U32, &v32, *(const ImU8*)p_min,  *(const ImU8*)p_max,  format, flags, out_grab_bb); if (r) *(ImU8*)p_v  = (ImU8)v32;  return r; }
    case SegaUiDataType_S16: { ImS32 v32 = (ImS32)*(ImS16*)p_v; bool r = SliderBehaviorT<ImS32, ImS32, float>(bb, id, SegaUiDataType_S32, &v32, *(const ImS16*)p_min, *(const ImS16*)p_max, format, flags, out_grab_bb); if (r) *(ImS16*)p_v = (ImS16)v32; return r; }
    case SegaUiDataType_U16: { ImU32 v32 = (ImU32)*(ImU16*)p_v; bool r = SliderBehaviorT<ImU32, ImS32, float>(bb, id, SegaUiDataType_U32, &v32, *(const ImU16*)p_min, *(const ImU16*)p_max, format, flags, out_grab_bb); if (r) *(ImU16*)p_v = (ImU16)v32; return r; }
    case SegaUiDataType_S32:
        IM_ASSERT(*(const ImS32*)p_min >= IM_S32_MIN / 2 && *(const ImS32*)p_max <= IM_S32_MAX / 2);
        return SliderBehaviorT<ImS32, ImS32, float >(bb, id, data_type, (ImS32*)p_v,  *(const ImS32*)p_min,  *(const ImS32*)p_max,  format, flags, out_grab_bb);
    case SegaUiDataType_U32:
        IM_ASSERT(*(const ImU32*)p_max <= IM_U32_MAX / 2);
        return SliderBehaviorT<ImU32, ImS32, float >(bb, id, data_type, (ImU32*)p_v,  *(const ImU32*)p_min,  *(const ImU32*)p_max,  format, flags, out_grab_bb);
    case SegaUiDataType_S64:
        IM_ASSERT(*(const ImS64*)p_min >= IM_S64_MIN / 2 && *(const ImS64*)p_max <= IM_S64_MAX / 2);
        return SliderBehaviorT<ImS64, ImS64, double>(bb, id, data_type, (ImS64*)p_v,  *(const ImS64*)p_min,  *(const ImS64*)p_max,  format, flags, out_grab_bb);
    case SegaUiDataType_U64:
        IM_ASSERT(*(const ImU64*)p_max <= IM_U64_MAX / 2);
        return SliderBehaviorT<ImU64, ImS64, double>(bb, id, data_type, (ImU64*)p_v,  *(const ImU64*)p_min,  *(const ImU64*)p_max,  format, flags, out_grab_bb);
    case SegaUiDataType_Float:
        IM_ASSERT(*(const float*)p_min >= -FLT_MAX / 2.0f && *(const float*)p_max <= FLT_MAX / 2.0f);
        return SliderBehaviorT<float, float, float >(bb, id, data_type, (float*)p_v,  *(const float*)p_min,  *(const float*)p_max,  format, flags, out_grab_bb);
    case SegaUiDataType_Double:
        IM_ASSERT(*(const double*)p_min >= -DBL_MAX / 2.0f && *(const double*)p_max <= DBL_MAX / 2.0f);
        return SliderBehaviorT<double, double, double>(bb, id, data_type, (double*)p_v, *(const double*)p_min, *(const double*)p_max, format, flags, out_grab_bb);
    case SegaUiDataType_COUNT: break;
    }
    IM_ASSERT(0);
    return false;
}

struct slider_state {
    ImVec4 background, circle, text;
    float slow_anim, circle_anim;
    int number_count;
};

namespace font
{
    extern ImFont* inter_bold;
    extern ImFont* inter_default;
}

bool SegaUi::SliderScalar(const char* label, SegaUiDataType data_type, void* p_data, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    const float w = GetContentRegionMax().x - style.WindowPadding.x;

    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const ImRect frame_bb(window->DC.CursorPos + ImVec2(0, label_size.y + 2), window->DC.CursorPos + ImVec2(w, label_size.y + 17.f));
    const ImRect total_bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? label_size.x : 0.0f, 0.0f));

    const bool temp_input_allowed = (flags & SegaUiSliderFlags_NoInput) == 0;
    ItemSize(ImRect(total_bb.Min, total_bb.Max + ImVec2(0, 14.f)));
    if (!ItemAdd(total_bb, id, &frame_bb, temp_input_allowed ? SegaUiItemFlags_Inputable : 0))
        return false;

    if (format == NULL) format = DataTypeGetInfo(data_type)->PrintFmt;

    const bool hovered = ItemHoverable(frame_bb, id);
    bool temp_input_is_active = temp_input_allowed && TempInputIsActive(id);
    if (!temp_input_is_active)
    {
        const bool input_requested_by_tabbing = temp_input_allowed && (g.LastItemData.StatusFlags & SegaUiItemStatusFlags_FocusedByTabbing) != 0;
        const bool clicked = hovered && IsMouseClicked(0, id);
        const bool make_active = (input_requested_by_tabbing || clicked || g.NavActivateId == id);
        if (make_active && clicked)
            SetKeyOwner(SegaUiKey_MouseLeft, id);
        if (make_active && temp_input_allowed)
            if (input_requested_by_tabbing || (clicked && g.IO.KeyCtrl) || (g.NavActivateId == id && (g.NavActivateFlags & SegaUiActivateFlags_PreferInput)))
                temp_input_is_active = true;

        if (make_active && !temp_input_is_active)
        {
            SetActiveID(id, window);
            SetFocusID(id, window);
            FocusWindow(window);
            g.ActiveIdUsingNavDirMask |= (1 << SegaUiDir_Left) | (1 << SegaUiDir_Right);
        }
    }

    ImRect grab_bb;

    static std::map<SegaUiID, slider_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, slider_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.circle_anim = ImLerp(it_anim->second.circle_anim, IsItemActive() ? 6.f : 6.5f, g.IO.DeltaTime * 6.f);
    it_anim->second.circle = ImLerp(it_anim->second.circle, IsItemActive() ? c::accent : c::slider::circle_inactive, g.IO.DeltaTime * 6.f);

    it_anim->second.text = ImLerp(it_anim->second.text, IsItemActive() ? c::text::text_active : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);

    GetWindowDrawList()->AddRectFilled(frame_bb.Min + ImVec2(0, 6), frame_bb.Max - ImVec2(0, 5), GetColorU32(c::slider::background), 100.f);

    const bool value_changed = SliderBehavior(frame_bb, id, data_type, p_data, p_min, p_max, format, flags, &grab_bb);
    if (value_changed)
        MarkItemEdited(id);

    char value_buf[64];
    const char* value_buf_end = value_buf + DataTypeFormatString(value_buf, IM_ARRAYSIZE(value_buf), data_type, p_data, format);

    if (grab_bb.Max.x > grab_bb.Min.x) {

        it_anim->second.slow_anim = ImLerp(it_anim->second.slow_anim, grab_bb.Min.x - frame_bb.Min.x, g.IO.DeltaTime * 25.f);

        GetWindowDrawList()->AddShadowRect(frame_bb.Min + ImVec2(1, 6), ImVec2(it_anim->second.slow_anim + frame_bb.Min.x + 3, grab_bb.Max.y - 4), GetColorU32(c::accent), 10.f, ImVec2(0, 0), 100.f);
        GetWindowDrawList()->AddRectFilled(frame_bb.Min + ImVec2(0, 6), ImVec2(it_anim->second.slow_anim + frame_bb.Min.x + 3, grab_bb.Max.y - 4), GetColorU32(c::accent), 100.f);

        GetWindowDrawList()->AddRectFilled(frame_bb.Min + ImVec2(it_anim->second.slow_anim - 2, -1), ImVec2(it_anim->second.slow_anim + frame_bb.Min.x + 15, grab_bb.Max.y + 3), GetColorU32(it_anim->second.circle), 2.f);

      //  GetWindowDrawList()->AddCircleFilled(ImVec2(it_anim->second.slow_anim + frame_bb.Min.x + 3, grab_bb.Max.y - 6), it_anim->second.circle_anim, GetColorU32(it_anim->second.circle), 100.f);

    }

    SegaUi::GlowText(font::inter_bold, 17.f, value_buf, ImVec2(frame_bb.Max.x - CalcTextSize(value_buf).x, frame_bb.Min.y - 22), GetColorU32(c::accent));

    GlowText(font::inter_default, 17.f, label, ImVec2(frame_bb.Max.x - w, frame_bb.Min.y - 22), GetColorU32(it_anim->second.text));


    //GetWindowDrawList()->AddText(ImVec2(frame_bb.Max.x - w, frame_bb.Min.y - 22), GetColorU32(it_anim->second.text), label);

    return value_changed;
}

// Add multiple sliders on 1 line for compact edition of multiple components
bool SegaUi::SliderScalarN(const char* label, SegaUiDataType data_type, void* v, int components, const void* v_min, const void* v_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    bool value_changed = false;
    BeginGroup();
    PushID(label);
    PushMultiItemsWidths(components, CalcItemWidth());
    size_t type_size = GDataTypeInfo[data_type].Size;
    for (int i = 0; i < components; i++)
    {
        PushID(i);
        if (i > 0)
            SameLine(0, g.Style.ItemInnerSpacing.x);
        value_changed |= SliderScalar("", data_type, v, v_min, v_max, format, flags);
        PopID();
        PopItemWidth();
        v = (void*)((char*)v + type_size);
    }
    PopID();

    const char* label_end = FindRenderedTextEnd(label);
    if (label != label_end)
    {
        SameLine(0, g.Style.ItemInnerSpacing.x);
        TextEx(label, label_end);
    }

    EndGroup();
    return value_changed;
}

bool SegaUi::SliderFloat(const char* label, float* v, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalar(label, SegaUiDataType_Float, v, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderFloat2(const char* label, float v[2], float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_Float, v, 2, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderFloat3(const char* label, float v[3], float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_Float, v, 3, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderFloat4(const char* label, float v[4], float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_Float, v, 4, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderAngle(const char* label, float* v_rad, float v_degrees_min, float v_degrees_max, const char* format, SegaUiSliderFlags flags)
{
    if (format == NULL)
        format = "%.0f deg";
    float v_deg = (*v_rad) * 360.0f / (2 * IM_PI);
    bool value_changed = SliderFloat(label, &v_deg, v_degrees_min, v_degrees_max, format, flags);
    *v_rad = v_deg * (2 * IM_PI) / 360.0f;
    return value_changed;
}

bool SegaUi::SliderInt(const char* label, int* v, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalar(label, SegaUiDataType_S32, v, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderInt2(const char* label, int v[2], int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_S32, v, 2, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderInt3(const char* label, int v[3], int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_S32, v, 3, &v_min, &v_max, format, flags);
}

bool SegaUi::SliderInt4(const char* label, int v[4], int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return SliderScalarN(label, SegaUiDataType_S32, v, 4, &v_min, &v_max, format, flags);
}

bool SegaUi::VSliderScalar(const char* label, const ImVec2& size, SegaUiDataType data_type, void* p_data, const void* p_min, const void* p_max, const char* format, SegaUiSliderFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);

    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + size);
    const ImRect bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f, 0.0f));

    ItemSize(bb, style.FramePadding.y);
    if (!ItemAdd(frame_bb, id))
        return false;

    // Default format string when passing NULL
    if (format == NULL)
        format = DataTypeGetInfo(data_type)->PrintFmt;

    const bool hovered = ItemHoverable(frame_bb, id);
    const bool clicked = hovered && IsMouseClicked(0, id);
    if (clicked || g.NavActivateId == id)
    {
        if (clicked)
            SetKeyOwner(SegaUiKey_MouseLeft, id);
        SetActiveID(id, window);
        SetFocusID(id, window);
        FocusWindow(window);
        g.ActiveIdUsingNavDirMask |= (1 << SegaUiDir_Up) | (1 << SegaUiDir_Down);
    }

    // Draw frame
    const ImU32 frame_col = GetColorU32(g.ActiveId == id ? SegaUiCol_FrameBgActive : hovered ? SegaUiCol_FrameBgHovered : SegaUiCol_FrameBg);
    RenderNavHighlight(frame_bb, id);
    RenderFrame(frame_bb.Min, frame_bb.Max, frame_col, true, g.Style.FrameRounding);

    // Slider behavior
    ImRect grab_bb;
    const bool value_changed = SliderBehavior(frame_bb, id, data_type, p_data, p_min, p_max, format, flags | SegaUiSliderFlags_Vertical, &grab_bb);
    if (value_changed)
        MarkItemEdited(id);

    // Render grab
    if (grab_bb.Max.y > grab_bb.Min.y)
        window->DrawList->AddRectFilled(grab_bb.Min, grab_bb.Max, GetColorU32(g.ActiveId == id ? SegaUiCol_SliderGrabActive : SegaUiCol_SliderGrab), style.GrabRounding);

    // Display value using user-provided display format so user can add prefix/suffix/decorations to the value.
    // For the vertical slider we allow centered text to overlap the frame padding
    char value_buf[64];
    const char* value_buf_end = value_buf + DataTypeFormatString(value_buf, IM_ARRAYSIZE(value_buf), data_type, p_data, format);
    RenderTextClipped(ImVec2(frame_bb.Min.x, frame_bb.Min.y + style.FramePadding.y), frame_bb.Max, value_buf, value_buf_end, NULL, ImVec2(0.5f, 0.0f));
    if (label_size.x > 0.0f)
        RenderText(ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x, frame_bb.Min.y + style.FramePadding.y), label);

    return value_changed;
}

bool SegaUi::VSliderFloat(const char* label, const ImVec2& size, float* v, float v_min, float v_max, const char* format, SegaUiSliderFlags flags)
{
    return VSliderScalar(label, size, SegaUiDataType_Float, v, &v_min, &v_max, format, flags);
}

bool SegaUi::VSliderInt(const char* label, const ImVec2& size, int* v, int v_min, int v_max, const char* format, SegaUiSliderFlags flags)
{
    return VSliderScalar(label, size, SegaUiDataType_S32, v, &v_min, &v_max, format, flags);
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: InputScalar, InputFloat, InputInt, etc.
//-------------------------------------------------------------------------
// - ImParseFormatFindStart() [Internal]
// - ImParseFormatFindEnd() [Internal]
// - ImParseFormatTrimDecorations() [Internal]
// - ImParseFormatSanitizeForPrinting() [Internal]
// - ImParseFormatSanitizeForScanning() [Internal]
// - ImParseFormatPrecision() [Internal]
// - TempInputTextScalar() [Internal]
// - InputScalar()
// - InputScalarN()
// - InputFloat()
// - InputFloat2()
// - InputFloat3()
// - InputFloat4()
// - InputInt()
// - InputInt2()
// - InputInt3()
// - InputInt4()
// - InputDouble()
//-------------------------------------------------------------------------

// We don't use strchr() because our strings are usually very short and often start with '%'
const char* ImParseFormatFindStart(const char* fmt)
{
    while (char c = fmt[0])
    {
        if (c == '%' && fmt[1] != '%')
            return fmt;
        else if (c == '%')
            fmt++;
        fmt++;
    }
    return fmt;
}

const char* ImParseFormatFindEnd(const char* fmt)
{
    // Printf/scanf types modifiers: I/L/h/j/l/t/w/z. Other uppercase letters qualify as types aka end of the format.
    if (fmt[0] != '%')
        return fmt;
    const unsigned int ignored_uppercase_mask = (1 << ('I'-'A')) | (1 << ('L'-'A'));
    const unsigned int ignored_lowercase_mask = (1 << ('h'-'a')) | (1 << ('j'-'a')) | (1 << ('l'-'a')) | (1 << ('t'-'a')) | (1 << ('w'-'a')) | (1 << ('z'-'a'));
    for (char c; (c = *fmt) != 0; fmt++)
    {
        if (c >= 'A' && c <= 'Z' && ((1 << (c - 'A')) & ignored_uppercase_mask) == 0)
            return fmt + 1;
        if (c >= 'a' && c <= 'z' && ((1 << (c - 'a')) & ignored_lowercase_mask) == 0)
            return fmt + 1;
    }
    return fmt;
}

// Extract the format out of a format string with leading or trailing decorations
//  fmt = "blah blah"  -> return ""
//  fmt = "%.3f"       -> return fmt
//  fmt = "hello %.3f" -> return fmt + 6
//  fmt = "%.3f hello" -> return buf written with "%.3f"
const char* ImParseFormatTrimDecorations(const char* fmt, char* buf, size_t buf_size)
{
    const char* fmt_start = ImParseFormatFindStart(fmt);
    if (fmt_start[0] != '%')
        return "";
    const char* fmt_end = ImParseFormatFindEnd(fmt_start);
    if (fmt_end[0] == 0) // If we only have leading decoration, we don't need to copy the data.
        return fmt_start;
    ImStrncpy(buf, fmt_start, ImMin((size_t)(fmt_end - fmt_start) + 1, buf_size));
    return buf;
}

// Sanitize format
// - Zero terminate so extra characters after format (e.g. "%f123") don't confuse atof/atoi
// - stb_sprintf.h supports several new modifiers which format numbers in a way that also makes them incompatible atof/atoi.
void ImParseFormatSanitizeForPrinting(const char* fmt_in, char* fmt_out, size_t fmt_out_size)
{
    const char* fmt_end = ImParseFormatFindEnd(fmt_in);
    IM_UNUSED(fmt_out_size);
    IM_ASSERT((size_t)(fmt_end - fmt_in + 1) < fmt_out_size); // Format is too long, let us know if this happens to you!
    while (fmt_in < fmt_end)
    {
        char c = *fmt_in++;
        if (c != '\'' && c != '$' && c != '_') // Custom flags provided by stb_sprintf.h. POSIX 2008 also supports '.
            *(fmt_out++) = c;
    }
    *fmt_out = 0; // Zero-terminate
}

// - For scanning we need to remove all width and precision fields and flags "%+3.7f" -> "%f". BUT don't strip types like "%I64d" which includes digits. ! "%07I64d" -> "%I64d"
const char* ImParseFormatSanitizeForScanning(const char* fmt_in, char* fmt_out, size_t fmt_out_size)
{
    const char* fmt_end = ImParseFormatFindEnd(fmt_in);
    const char* fmt_out_begin = fmt_out;
    IM_UNUSED(fmt_out_size);
    IM_ASSERT((size_t)(fmt_end - fmt_in + 1) < fmt_out_size); // Format is too long, let us know if this happens to you!
    bool has_type = false;
    while (fmt_in < fmt_end)
    {
        char c = *fmt_in++;
        if (!has_type && ((c >= '0' && c <= '9') || c == '.' || c == '+' || c == '#'))
            continue;
        has_type |= ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')); // Stop skipping digits
        if (c != '\'' && c != '$' && c != '_') // Custom flags provided by stb_sprintf.h. POSIX 2008 also supports '.
            *(fmt_out++) = c;
    }
    *fmt_out = 0; // Zero-terminate
    return fmt_out_begin;
}

template<typename TYPE>
static const char* ImAtoi(const char* src, TYPE* output)
{
    int negative = 0;
    if (*src == '-') { negative = 1; src++; }
    if (*src == '+') { src++; }
    TYPE v = 0;
    while (*src >= '0' && *src <= '9')
        v = (v * 10) + (*src++ - '0');
    *output = negative ? -v : v;
    return src;
}

// Parse display precision back from the display format string
// FIXME: This is still used by some navigation code path to infer a minimum tweak step, but we should aim to rework widgets so it isn't needed.
int ImParseFormatPrecision(const char* fmt, int default_precision)
{
    fmt = ImParseFormatFindStart(fmt);
    if (fmt[0] != '%')
        return default_precision;
    fmt++;
    while (*fmt >= '0' && *fmt <= '9')
        fmt++;
    int precision = INT_MAX;
    if (*fmt == '.')
    {
        fmt = ImAtoi<int>(fmt + 1, &precision);
        if (precision < 0 || precision > 99)
            precision = default_precision;
    }
    if (*fmt == 'e' || *fmt == 'E') // Maximum precision with scientific notation
        precision = -1;
    if ((*fmt == 'g' || *fmt == 'G') && precision == INT_MAX)
        precision = -1;
    return (precision == INT_MAX) ? default_precision : precision;
}

// Create text input in place of another active widget (e.g. used when doing a CTRL+Click on drag/slider widgets)
// FIXME: Facilitate using this in variety of other situations.
bool SegaUi::TempInputText(const ImRect& bb, SegaUiID id, const char* label, char* buf, int buf_size, SegaUiInputTextFlags flags)
{
    // On the first frame, g.TempInputTextId == 0, then on subsequent frames it becomes == id.
    // We clear ActiveID on the first frame to allow the InputText() taking it back.
    SegaUiContext& g = *GSegaUi;
    const bool init = (g.TempInputId != id);
    if (init)
        ClearActiveID();

    g.CurrentWindow->DC.CursorPos = bb.Min;
    bool value_changed = InputTextEx(label, NULL, buf, buf_size, bb.GetSize(), flags | SegaUiInputTextFlags_MergedItem);
    if (init)
    {
        // First frame we started displaying the InputText widget, we expect it to take the active id.
        IM_ASSERT(g.ActiveId == id);
        g.TempInputId = g.ActiveId;
    }
    return value_changed;
}

static inline SegaUiInputTextFlags InputScalar_DefaultCharsFilter(SegaUiDataType data_type, const char* format)
{
    if (data_type == SegaUiDataType_Float || data_type == SegaUiDataType_Double)
        return SegaUiInputTextFlags_CharsScientific;
    const char format_last_char = format[0] ? format[strlen(format) - 1] : 0;
    return (format_last_char == 'x' || format_last_char == 'X') ? SegaUiInputTextFlags_CharsHexadecimal : SegaUiInputTextFlags_CharsDecimal;
}

// Note that Drag/Slider functions are only forwarding the min/max values clamping values if the SegaUiSliderFlags_AlwaysClamp flag is set!
// This is intended: this way we allow CTRL+Click manual input to set a value out of bounds, for maximum flexibility.
// However this may not be ideal for all uses, as some user code may break on out of bound values.
bool SegaUi::TempInputScalar(const ImRect& bb, SegaUiID id, const char* label, SegaUiDataType data_type, void* p_data, const char* format, const void* p_clamp_min, const void* p_clamp_max)
{
    // FIXME: May need to clarify display behavior if format doesn't contain %.
    // "%d" -> "%d" / "There are %d items" -> "%d" / "items" -> "%d" (fallback). Also see #6405
    const SegaUiDataTypeInfo* type_info = DataTypeGetInfo(data_type);
    char fmt_buf[32];
    char data_buf[32];
    format = ImParseFormatTrimDecorations(format, fmt_buf, IM_ARRAYSIZE(fmt_buf));
    if (format[0] == 0)
        format = type_info->PrintFmt;
    DataTypeFormatString(data_buf, IM_ARRAYSIZE(data_buf), data_type, p_data, format);
    ImStrTrimBlanks(data_buf);

    SegaUiInputTextFlags flags = SegaUiInputTextFlags_AutoSelectAll | SegaUiInputTextFlags_NoMarkEdited;
    flags |= InputScalar_DefaultCharsFilter(data_type, format);

    bool value_changed = false;
    if (TempInputText(bb, id, label, data_buf, IM_ARRAYSIZE(data_buf), flags))
    {
        // Backup old value
        size_t data_type_size = type_info->Size;
        SegaUiDataTypeTempStorage data_backup;
        memcpy(&data_backup, p_data, data_type_size);

        // Apply new value (or operations) then clamp
        DataTypeApplyFromText(data_buf, data_type, p_data, format);
        if (p_clamp_min || p_clamp_max)
        {
            if (p_clamp_min && p_clamp_max && DataTypeCompare(data_type, p_clamp_min, p_clamp_max) > 0)
                ImSwap(p_clamp_min, p_clamp_max);
            DataTypeClamp(data_type, p_data, p_clamp_min, p_clamp_max);
        }

        // Only mark as edited if new value is different
        value_changed = memcmp(&data_backup, p_data, data_type_size) != 0;
        if (value_changed)
            MarkItemEdited(id);
    }
    return value_changed;
}

// Note: p_data, p_step, p_step_fast are _pointers_ to a memory address holding the data. For an Input widget, p_step and p_step_fast are optional.
// Read code of e.g. InputFloat(), InputInt() etc. or examples in 'Demo->Widgets->Data Types' to understand how to use this function directly.
bool SegaUi::InputScalar(const char* label, SegaUiDataType data_type, void* p_data, const void* p_step, const void* p_step_fast, const char* format, SegaUiInputTextFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    SegaUiStyle& style = g.Style;

    if (format == NULL)
        format = DataTypeGetInfo(data_type)->PrintFmt;

    char buf[64];
    DataTypeFormatString(buf, IM_ARRAYSIZE(buf), data_type, p_data, format);

    // Testing ActiveId as a minor optimization as filtering is not needed until active
    if (g.ActiveId == 0 && (flags & (SegaUiInputTextFlags_CharsDecimal | SegaUiInputTextFlags_CharsHexadecimal | SegaUiInputTextFlags_CharsScientific)) == 0)
        flags |= InputScalar_DefaultCharsFilter(data_type, format);
    flags |= SegaUiInputTextFlags_AutoSelectAll | SegaUiInputTextFlags_NoMarkEdited; // We call MarkItemEdited() ourselves by comparing the actual data rather than the string.

    bool value_changed = false;
    if (p_step == NULL)
    {
        if (InputText(label, buf, IM_ARRAYSIZE(buf), flags))
            value_changed = DataTypeApplyFromText(buf, data_type, p_data, format);
    }
    else
    {
        const float button_size = GetFrameHeight();

        BeginGroup(); // The only purpose of the group here is to allow the caller to query item data e.g. IsItemActive()
        PushID(label);
        SetNextItemWidth(ImMax(1.0f, CalcItemWidth() - (button_size + style.ItemInnerSpacing.x) * 2));
        if (InputText("", buf, IM_ARRAYSIZE(buf), flags)) // PushId(label) + "" gives us the expected ID from outside point of view
            value_changed = DataTypeApplyFromText(buf, data_type, p_data, format);
        SEGAUI_TEST_ENGINE_ITEM_INFO(g.LastItemData.ID, label, g.LastItemData.StatusFlags | SegaUiItemStatusFlags_Inputable);

        // Step buttons
        const ImVec2 backup_frame_padding = style.FramePadding;
        style.FramePadding.x = style.FramePadding.y;
        SegaUiButtonFlags button_flags = SegaUiButtonFlags_Repeat | SegaUiButtonFlags_DontClosePopups;
        if (flags & SegaUiInputTextFlags_ReadOnly)
            BeginDisabled();
        SameLine(0, style.ItemInnerSpacing.x);
        if (ButtonEx("-", ImVec2(button_size, button_size), button_flags))
        {
            DataTypeApplyOp(data_type, '-', p_data, p_data, g.IO.KeyCtrl && p_step_fast ? p_step_fast : p_step);
            value_changed = true;
        }
        SameLine(0, style.ItemInnerSpacing.x);
        if (ButtonEx("+", ImVec2(button_size, button_size), button_flags))
        {
            DataTypeApplyOp(data_type, '+', p_data, p_data, g.IO.KeyCtrl && p_step_fast ? p_step_fast : p_step);
            value_changed = true;
        }
        if (flags & SegaUiInputTextFlags_ReadOnly)
            EndDisabled();

        const char* label_end = FindRenderedTextEnd(label);
        if (label != label_end)
        {
            SameLine(0, style.ItemInnerSpacing.x);
            TextEx(label, label_end);
        }
        style.FramePadding = backup_frame_padding;

        PopID();
        EndGroup();
    }
    if (value_changed)
        MarkItemEdited(g.LastItemData.ID);

    return value_changed;
}

bool SegaUi::InputScalarN(const char* label, SegaUiDataType data_type, void* p_data, int components, const void* p_step, const void* p_step_fast, const char* format, SegaUiInputTextFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    bool value_changed = false;
    BeginGroup();
    PushID(label);
    PushMultiItemsWidths(components, CalcItemWidth());
    size_t type_size = GDataTypeInfo[data_type].Size;
    for (int i = 0; i < components; i++)
    {
        PushID(i);
        if (i > 0)
            SameLine(0, g.Style.ItemInnerSpacing.x);
        value_changed |= InputScalar("", data_type, p_data, p_step, p_step_fast, format, flags);
        PopID();
        PopItemWidth();
        p_data = (void*)((char*)p_data + type_size);
    }
    PopID();

    const char* label_end = FindRenderedTextEnd(label);
    if (label != label_end)
    {
        SameLine(0.0f, g.Style.ItemInnerSpacing.x);
        TextEx(label, label_end);
    }

    EndGroup();
    return value_changed;
}

bool SegaUi::InputFloat(const char* label, float* v, float step, float step_fast, const char* format, SegaUiInputTextFlags flags)
{
    flags |= SegaUiInputTextFlags_CharsScientific;
    return InputScalar(label, SegaUiDataType_Float, (void*)v, (void*)(step > 0.0f ? &step : NULL), (void*)(step_fast > 0.0f ? &step_fast : NULL), format, flags);
}

bool SegaUi::InputFloat2(const char* label, float v[2], const char* format, SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_Float, v, 2, NULL, NULL, format, flags);
}

bool SegaUi::InputFloat3(const char* label, float v[3], const char* format, SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_Float, v, 3, NULL, NULL, format, flags);
}

bool SegaUi::InputFloat4(const char* label, float v[4], const char* format, SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_Float, v, 4, NULL, NULL, format, flags);
}

bool SegaUi::InputInt(const char* label, int* v, int step, int step_fast, SegaUiInputTextFlags flags)
{
    // Hexadecimal input provided as a convenience but the flag name is awkward. Typically you'd use InputText() to parse your own data, if you want to handle prefixes.
    const char* format = (flags & SegaUiInputTextFlags_CharsHexadecimal) ? "%08X" : "%d";
    return InputScalar(label, SegaUiDataType_S32, (void*)v, (void*)(step > 0 ? &step : NULL), (void*)(step_fast > 0 ? &step_fast : NULL), format, flags);
}

bool SegaUi::InputInt2(const char* label, int v[2], SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_S32, v, 2, NULL, NULL, "%d", flags);
}

bool SegaUi::InputInt3(const char* label, int v[3], SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_S32, v, 3, NULL, NULL, "%d", flags);
}

bool SegaUi::InputInt4(const char* label, int v[4], SegaUiInputTextFlags flags)
{
    return InputScalarN(label, SegaUiDataType_S32, v, 4, NULL, NULL, "%d", flags);
}

bool SegaUi::InputDouble(const char* label, double* v, double step, double step_fast, const char* format, SegaUiInputTextFlags flags)
{
    flags |= SegaUiInputTextFlags_CharsScientific;
    return InputScalar(label, SegaUiDataType_Double, (void*)v, (void*)(step > 0.0 ? &step : NULL), (void*)(step_fast > 0.0 ? &step_fast : NULL), format, flags);
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: InputText, InputTextMultiline, InputTextWithHint
//-------------------------------------------------------------------------
// - InputText()
// - InputTextWithHint()
// - InputTextMultiline()
// - InputTextGetCharInfo() [Internal]
// - InputTextReindexLines() [Internal]
// - InputTextReindexLinesRange() [Internal]
// - InputTextEx() [Internal]
// - DebugNodeInputTextState() [Internal]
//-------------------------------------------------------------------------

bool SegaUi::InputText(const char* label, char* buf, size_t buf_size, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* user_data)
{
    IM_ASSERT(!(flags & SegaUiInputTextFlags_Multiline)); // call InputTextMultiline()
    return InputTextEx(label, NULL, buf, (int)buf_size, ImVec2(0, 0), flags, callback, user_data);
}

bool SegaUi::InputTextMultiline(const char* label, char* buf, size_t buf_size, const ImVec2& size, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* user_data)
{
    return InputTextEx(label, NULL, buf, (int)buf_size, size, flags | SegaUiInputTextFlags_Multiline, callback, user_data);
}

bool SegaUi::InputTextWithHint(const char* label, const char* hint, char* buf, size_t buf_size, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* user_data)
{
    IM_ASSERT(!(flags & SegaUiInputTextFlags_Multiline)); // call InputTextMultiline() or  InputTextEx() manually if you need multi-line + hint.
    return InputTextEx(label, hint, buf, (int)buf_size, ImVec2(0, 0), flags, callback, user_data);
}

static int InputTextCalcTextLenAndLineCount(const char* text_begin, const char** out_text_end)
{
    int line_count = 0;
    const char* s = text_begin;
    while (char c = *s++) // We are only matching for \n so we can ignore UTF-8 decoding
        if (c == '\n')
            line_count++;
    s--;
    if (s[0] != '\n' && s[0] != '\r')
        line_count++;
    *out_text_end = s;
    return line_count;
}

static ImVec2 InputTextCalcTextSizeW(SegaUiContext* ctx, const ImWchar* text_begin, const ImWchar* text_end, const ImWchar** remaining, ImVec2* out_offset, bool stop_on_new_line)
{
    SegaUiContext& g = *ctx;
    ImFont* font = g.Font;
    const float line_height = g.FontSize;
    const float scale = line_height / font->FontSize;

    ImVec2 text_size = ImVec2(0, 0);
    float line_width = 0.0f;

    const ImWchar* s = text_begin;
    while (s < text_end)
    {
        unsigned int c = (unsigned int)(*s++);
        if (c == '\n')
        {
            text_size.x = ImMax(text_size.x, line_width);
            text_size.y += line_height;
            line_width = 0.0f;
            if (stop_on_new_line)
                break;
            continue;
        }
        if (c == '\r')
            continue;

        const float char_width = font->GetCharAdvance((ImWchar)c) * scale;
        line_width += char_width;
    }

    if (text_size.x < line_width)
        text_size.x = line_width;

    if (out_offset)
        *out_offset = ImVec2(line_width, text_size.y + line_height);  // offset allow for the possibility of sitting after a trailing \n

    if (line_width > 0 || text_size.y == 0.0f)                        // whereas size.y will ignore the trailing \n
        text_size.y += line_height;

    if (remaining)
        *remaining = s;

    return text_size;
}

// Wrapper for stb_textedit.h to edit text (our wrapper is for: statically sized buffer, single-line, wchar characters. InputText converts between UTF-8 and wchar)
namespace ImStb
{

static int     STB_TEXTEDIT_STRINGLEN(const SegaUiInputTextState* obj)                             { return obj->CurLenW; }
static ImWchar STB_TEXTEDIT_GETCHAR(const SegaUiInputTextState* obj, int idx)                      { return obj->TextW[idx]; }
static float   STB_TEXTEDIT_GETWIDTH(SegaUiInputTextState* obj, int line_start_idx, int char_idx)  { ImWchar c = obj->TextW[line_start_idx + char_idx]; if (c == '\n') return STB_TEXTEDIT_GETWIDTH_NEWLINE; SegaUiContext& g = *obj->Ctx; return g.Font->GetCharAdvance(c) * (g.FontSize / g.Font->FontSize); }
static int     STB_TEXTEDIT_KEYTOTEXT(int key)                                                    { return key >= 0x200000 ? 0 : key; }
static ImWchar STB_TEXTEDIT_NEWLINE = '\n';
static void    STB_TEXTEDIT_LAYOUTROW(StbTexteditRow* r, SegaUiInputTextState* obj, int line_start_idx)
{
    const ImWchar* text = obj->TextW.Data;
    const ImWchar* text_remaining = NULL;
    const ImVec2 size = InputTextCalcTextSizeW(obj->Ctx, text + line_start_idx, text + obj->CurLenW, &text_remaining, NULL, true);
    r->x0 = 0.0f;
    r->x1 = size.x;
    r->baseline_y_delta = size.y;
    r->ymin = 0.0f;
    r->ymax = size.y;
    r->num_chars = (int)(text_remaining - (text + line_start_idx));
}

static bool is_separator(unsigned int c)
{
    return c==',' || c==';' || c=='(' || c==')' || c=='{' || c=='}' || c=='[' || c==']' || c=='|' || c=='\n' || c=='\r' || c=='.' || c=='!';
}

static int is_word_boundary_from_right(SegaUiInputTextState* obj, int idx)
{
    // When SegaUiInputTextFlags_Password is set, we don't want actions such as CTRL+Arrow to leak the fact that underlying data are blanks or separators.
    if ((obj->Flags & SegaUiInputTextFlags_Password) || idx <= 0)
        return 0;

    bool prev_white = ImCharIsBlankW(obj->TextW[idx - 1]);
    bool prev_separ = is_separator(obj->TextW[idx - 1]);
    bool curr_white = ImCharIsBlankW(obj->TextW[idx]);
    bool curr_separ = is_separator(obj->TextW[idx]);
    return ((prev_white || prev_separ) && !(curr_separ || curr_white)) || (curr_separ && !prev_separ);
}
static int is_word_boundary_from_left(SegaUiInputTextState* obj, int idx)
{
    if ((obj->Flags & SegaUiInputTextFlags_Password) || idx <= 0)
        return 0;

    bool prev_white = ImCharIsBlankW(obj->TextW[idx]);
    bool prev_separ = is_separator(obj->TextW[idx]);
    bool curr_white = ImCharIsBlankW(obj->TextW[idx - 1]);
    bool curr_separ = is_separator(obj->TextW[idx - 1]);
    return ((prev_white) && !(curr_separ || curr_white)) || (curr_separ && !prev_separ);
}
static int  STB_TEXTEDIT_MOVEWORDLEFT_IMPL(SegaUiInputTextState* obj, int idx)   { idx--; while (idx >= 0 && !is_word_boundary_from_right(obj, idx)) idx--; return idx < 0 ? 0 : idx; }
static int  STB_TEXTEDIT_MOVEWORDRIGHT_MAC(SegaUiInputTextState* obj, int idx)   { idx++; int len = obj->CurLenW; while (idx < len && !is_word_boundary_from_left(obj, idx)) idx++; return idx > len ? len : idx; }
static int  STB_TEXTEDIT_MOVEWORDRIGHT_WIN(SegaUiInputTextState* obj, int idx)   { idx++; int len = obj->CurLenW; while (idx < len && !is_word_boundary_from_right(obj, idx)) idx++; return idx > len ? len : idx; }
static int  STB_TEXTEDIT_MOVEWORDRIGHT_IMPL(SegaUiInputTextState* obj, int idx)  { SegaUiContext& g = *obj->Ctx; if (g.IO.ConfigMacOSXBehaviors) return STB_TEXTEDIT_MOVEWORDRIGHT_MAC(obj, idx); else return STB_TEXTEDIT_MOVEWORDRIGHT_WIN(obj, idx); }
#define STB_TEXTEDIT_MOVEWORDLEFT   STB_TEXTEDIT_MOVEWORDLEFT_IMPL  // They need to be #define for stb_textedit.h
#define STB_TEXTEDIT_MOVEWORDRIGHT  STB_TEXTEDIT_MOVEWORDRIGHT_IMPL

static void STB_TEXTEDIT_DELETECHARS(SegaUiInputTextState* obj, int pos, int n)
{
    ImWchar* dst = obj->TextW.Data + pos;

    // We maintain our buffer length in both UTF-8 and wchar formats
    obj->Edited = true;
    obj->CurLenA -= ImTextCountUtf8BytesFromStr(dst, dst + n);
    obj->CurLenW -= n;

    // Offset remaining text (FIXME-OPT: Use memmove)
    const ImWchar* src = obj->TextW.Data + pos + n;
    while (ImWchar c = *src++)
        *dst++ = c;
    *dst = '\0';
}

static bool STB_TEXTEDIT_INSERTCHARS(SegaUiInputTextState* obj, int pos, const ImWchar* new_text, int new_text_len)
{
    const bool is_resizable = (obj->Flags & SegaUiInputTextFlags_CallbackResize) != 0;
    const int text_len = obj->CurLenW;
    IM_ASSERT(pos <= text_len);

    const int new_text_len_utf8 = ImTextCountUtf8BytesFromStr(new_text, new_text + new_text_len);
    if (!is_resizable && (new_text_len_utf8 + obj->CurLenA + 1 > obj->BufCapacityA))
        return false;

    // Grow internal buffer if needed
    if (new_text_len + text_len + 1 > obj->TextW.Size)
    {
        if (!is_resizable)
            return false;
        IM_ASSERT(text_len < obj->TextW.Size);
        obj->TextW.resize(text_len + ImClamp(new_text_len * 4, 32, ImMax(256, new_text_len)) + 1);
    }

    ImWchar* text = obj->TextW.Data;
    if (pos != text_len)
        memmove(text + pos + new_text_len, text + pos, (size_t)(text_len - pos) * sizeof(ImWchar));
    memcpy(text + pos, new_text, (size_t)new_text_len * sizeof(ImWchar));

    obj->Edited = true;
    obj->CurLenW += new_text_len;
    obj->CurLenA += new_text_len_utf8;
    obj->TextW[obj->CurLenW] = '\0';

    return true;
}

// We don't use an enum so we can build even with conflicting symbols (if another user of stb_textedit.h leak their STB_TEXTEDIT_K_* symbols)
#define STB_TEXTEDIT_K_LEFT         0x200000 // keyboard input to move cursor left
#define STB_TEXTEDIT_K_RIGHT        0x200001 // keyboard input to move cursor right
#define STB_TEXTEDIT_K_UP           0x200002 // keyboard input to move cursor up
#define STB_TEXTEDIT_K_DOWN         0x200003 // keyboard input to move cursor down
#define STB_TEXTEDIT_K_LINESTART    0x200004 // keyboard input to move cursor to start of line
#define STB_TEXTEDIT_K_LINEEND      0x200005 // keyboard input to move cursor to end of line
#define STB_TEXTEDIT_K_TEXTSTART    0x200006 // keyboard input to move cursor to start of text
#define STB_TEXTEDIT_K_TEXTEND      0x200007 // keyboard input to move cursor to end of text
#define STB_TEXTEDIT_K_DELETE       0x200008 // keyboard input to delete selection or character under cursor
#define STB_TEXTEDIT_K_BACKSPACE    0x200009 // keyboard input to delete selection or character left of cursor
#define STB_TEXTEDIT_K_UNDO         0x20000A // keyboard input to perform undo
#define STB_TEXTEDIT_K_REDO         0x20000B // keyboard input to perform redo
#define STB_TEXTEDIT_K_WORDLEFT     0x20000C // keyboard input to move cursor left one word
#define STB_TEXTEDIT_K_WORDRIGHT    0x20000D // keyboard input to move cursor right one word
#define STB_TEXTEDIT_K_PGUP         0x20000E // keyboard input to move cursor up a page
#define STB_TEXTEDIT_K_PGDOWN       0x20000F // keyboard input to move cursor down a page
#define STB_TEXTEDIT_K_SHIFT        0x400000

#define STB_TEXTEDIT_IMPLEMENTATION
#include "imstb_textedit.h"

// stb_textedit internally allows for a single undo record to do addition and deletion, but somehow, calling
// the stb_textedit_paste() function creates two separate records, so we perform it manually. (FIXME: Report to nothings/stb?)
static void stb_textedit_replace(SegaUiInputTextState* str, STB_TexteditState* state, const STB_TEXTEDIT_CHARTYPE* text, int text_len)
{
    stb_text_makeundo_replace(str, state, 0, str->CurLenW, text_len);
    ImStb::STB_TEXTEDIT_DELETECHARS(str, 0, str->CurLenW);
    state->cursor = state->select_start = state->select_end = 0;
    if (text_len <= 0)
        return;
    if (ImStb::STB_TEXTEDIT_INSERTCHARS(str, 0, text, text_len))
    {
        state->cursor = state->select_start = state->select_end = text_len;
        state->has_preferred_x = 0;
        return;
    }
    IM_ASSERT(0); // Failed to insert character, normally shouldn't happen because of how we currently use stb_textedit_replace()
}

} // namespace ImStb

void SegaUiInputTextState::OnKeyPressed(int key)
{
    stb_textedit_key(this, &Stb, key);
    CursorFollow = true;
    CursorAnimReset();
}

SegaUiInputTextCallbackData::SegaUiInputTextCallbackData()
{
    memset(this, 0, sizeof(*this));
}

// Public API to manipulate UTF-8 text
// We expose UTF-8 to the user (unlike the STB_TEXTEDIT_* functions which are manipulating wchar)
// FIXME: The existence of this rarely exercised code path is a bit of a nuisance.
void SegaUiInputTextCallbackData::DeleteChars(int pos, int bytes_count)
{
    IM_ASSERT(pos + bytes_count <= BufTextLen);
    char* dst = Buf + pos;
    const char* src = Buf + pos + bytes_count;
    while (char c = *src++)
        *dst++ = c;
    *dst = '\0';

    if (CursorPos >= pos + bytes_count)
        CursorPos -= bytes_count;
    else if (CursorPos >= pos)
        CursorPos = pos;
    SelectionStart = SelectionEnd = CursorPos;
    BufDirty = true;
    BufTextLen -= bytes_count;
}

void SegaUiInputTextCallbackData::InsertChars(int pos, const char* new_text, const char* new_text_end)
{
    const bool is_resizable = (Flags & SegaUiInputTextFlags_CallbackResize) != 0;
    const int new_text_len = new_text_end ? (int)(new_text_end - new_text) : (int)strlen(new_text);
    if (new_text_len + BufTextLen >= BufSize)
    {
        if (!is_resizable)
            return;

        // Contrary to STB_TEXTEDIT_INSERTCHARS() this is working in the UTF8 buffer, hence the mildly similar code (until we remove the U16 buffer altogether!)
        SegaUiContext& g = *Ctx;
        SegaUiInputTextState* edit_state = &g.InputTextState;
        IM_ASSERT(edit_state->ID != 0 && g.ActiveId == edit_state->ID);
        IM_ASSERT(Buf == edit_state->TextA.Data);
        int new_buf_size = BufTextLen + ImClamp(new_text_len * 4, 32, ImMax(256, new_text_len)) + 1;
        edit_state->TextA.reserve(new_buf_size + 1);
        Buf = edit_state->TextA.Data;
        BufSize = edit_state->BufCapacityA = new_buf_size;
    }

    if (BufTextLen != pos)
        memmove(Buf + pos + new_text_len, Buf + pos, (size_t)(BufTextLen - pos));
    memcpy(Buf + pos, new_text, (size_t)new_text_len * sizeof(char));
    Buf[BufTextLen + new_text_len] = '\0';

    if (CursorPos >= pos)
        CursorPos += new_text_len;
    SelectionStart = SelectionEnd = CursorPos;
    BufDirty = true;
    BufTextLen += new_text_len;
}

// Return false to discard a character.
static bool InputTextFilterCharacter(unsigned int* p_char, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* user_data, SegaUiInputSource input_source)
{
    IM_ASSERT(input_source == SegaUiInputSource_Keyboard || input_source == SegaUiInputSource_Clipboard);
    unsigned int c = *p_char;

    // Filter non-printable (NB: isprint is unreliable! see #2467)
    bool apply_named_filters = true;
    if (c < 0x20)
    {
        bool pass = false;
        pass |= (c == '\n' && (flags & SegaUiInputTextFlags_Multiline)); // Note that an Enter KEY will emit \r and be ignored (we poll for KEY in InputText() code)
        pass |= (c == '\t' && (flags & SegaUiInputTextFlags_AllowTabInput));
        if (!pass)
            return false;
        apply_named_filters = false; // Override named filters below so newline and tabs can still be inserted.
    }

    if (input_source != SegaUiInputSource_Clipboard)
    {
        // We ignore Ascii representation of delete (emitted from Backspace on OSX, see #2578, #2817)
        if (c == 127)
            return false;

        // Filter private Unicode range. GLFW on OSX seems to send private characters for special keys like arrow keys (FIXME)
        if (c >= 0xE000 && c <= 0xF8FF)
            return false;
    }

    // Filter Unicode ranges we are not handling in this build
    if (c > IM_UNICODE_CODEPOINT_MAX)
        return false;

    // Generic named filters
    if (apply_named_filters && (flags & (SegaUiInputTextFlags_CharsDecimal | SegaUiInputTextFlags_CharsHexadecimal | SegaUiInputTextFlags_CharsUppercase | SegaUiInputTextFlags_CharsNoBlank | SegaUiInputTextFlags_CharsScientific)))
    {
        // The libc allows overriding locale, with e.g. 'setlocale(LC_NUMERIC, "de_DE.UTF-8");' which affect the output/input of printf/scanf to use e.g. ',' instead of '.'.
        // The standard mandate that programs starts in the "C" locale where the decimal point is '.'.
        // We don't really intend to provide widespread support for it, but out of empathy for people stuck with using odd API, we support the bare minimum aka overriding the decimal point.
        // Change the default decimal_point with:
        //   SegaUi::GetCurrentContext()->PlatformLocaleDecimalPoint = *localeconv()->decimal_point;
        // Users of non-default decimal point (in particular ',') may be affected by word-selection logic (is_word_boundary_from_right/is_word_boundary_from_left) functions.
        SegaUiContext& g = *GSegaUi;
        const unsigned c_decimal_point = (unsigned int)g.PlatformLocaleDecimalPoint;

        // Full-width -> half-width conversion for numeric fields (https://en.wikipedia.org/wiki/Halfwidth_and_Fullwidth_Forms_(Unicode_block)
        // While this is mostly convenient, this has the side-effect for uninformed users accidentally inputting full-width characters that they may
        // scratch their head as to why it works in numerical fields vs in generic text fields it would require support in the font.
        if (flags & (SegaUiInputTextFlags_CharsDecimal | SegaUiInputTextFlags_CharsScientific | SegaUiInputTextFlags_CharsHexadecimal))
            if (c >= 0xFF01 && c <= 0xFF5E)
                c = c - 0xFF01 + 0x21;

        // Allow 0-9 . - + * /
        if (flags & SegaUiInputTextFlags_CharsDecimal)
            if (!(c >= '0' && c <= '9') && (c != c_decimal_point) && (c != '-') && (c != '+') && (c != '*') && (c != '/'))
                return false;

        // Allow 0-9 . - + * / e E
        if (flags & SegaUiInputTextFlags_CharsScientific)
            if (!(c >= '0' && c <= '9') && (c != c_decimal_point) && (c != '-') && (c != '+') && (c != '*') && (c != '/') && (c != 'e') && (c != 'E'))
                return false;

        // Allow 0-9 a-F A-F
        if (flags & SegaUiInputTextFlags_CharsHexadecimal)
            if (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F'))
                return false;

        // Turn a-z into A-Z
        if (flags & SegaUiInputTextFlags_CharsUppercase)
            if (c >= 'a' && c <= 'z')
                c += (unsigned int)('A' - 'a');

        if (flags & SegaUiInputTextFlags_CharsNoBlank)
            if (ImCharIsBlankW(c))
                return false;

        *p_char = c;
    }

    // Custom callback filter
    if (flags & SegaUiInputTextFlags_CallbackCharFilter)
    {
        SegaUiContext& g = *GSegaUi;
        SegaUiInputTextCallbackData callback_data;
        callback_data.Ctx = &g;
        callback_data.EventFlag = SegaUiInputTextFlags_CallbackCharFilter;
        callback_data.EventChar = (ImWchar)c;
        callback_data.Flags = flags;
        callback_data.UserData = user_data;
        if (callback(&callback_data) != 0)
            return false;
        *p_char = callback_data.EventChar;
        if (!callback_data.EventChar)
            return false;
    }

    return true;
}

// Find the shortest single replacement we can make to get the new text from the old text.
// Important: needs to be run before TextW is rewritten with the new characters because calling STB_TEXTEDIT_GETCHAR() at the end.
// FIXME: Ideally we should transition toward (1) making InsertChars()/DeleteChars() update undo-stack (2) discourage (and keep reconcile) or obsolete (and remove reconcile) accessing buffer directly.
static void InputTextReconcileUndoStateAfterUserCallback(SegaUiInputTextState* state, const char* new_buf_a, int new_length_a)
{
    SegaUiContext& g = *GSegaUi;
    const ImWchar* old_buf = state->TextW.Data;
    const int old_length = state->CurLenW;
    const int new_length = ImTextCountCharsFromUtf8(new_buf_a, new_buf_a + new_length_a);
    g.TempBuffer.reserve_discard((new_length + 1) * sizeof(ImWchar));
    ImWchar* new_buf = (ImWchar*)(void*)g.TempBuffer.Data;
    ImTextStrFromUtf8(new_buf, new_length + 1, new_buf_a, new_buf_a + new_length_a);

    const int shorter_length = ImMin(old_length, new_length);
    int first_diff;
    for (first_diff = 0; first_diff < shorter_length; first_diff++)
        if (old_buf[first_diff] != new_buf[first_diff])
            break;
    if (first_diff == old_length && first_diff == new_length)
        return;

    int old_last_diff = old_length - 1;
    int new_last_diff = new_length - 1;
    for (; old_last_diff >= first_diff && new_last_diff >= first_diff; old_last_diff--, new_last_diff--)
        if (old_buf[old_last_diff] != new_buf[new_last_diff])
            break;

    const int insert_len = new_last_diff - first_diff + 1;
    const int delete_len = old_last_diff - first_diff + 1;
    if (insert_len > 0 || delete_len > 0)
        if (STB_TEXTEDIT_CHARTYPE* p = stb_text_createundo(&state->Stb.undostate, first_diff, delete_len, insert_len))
            for (int i = 0; i < delete_len; i++)
                p[i] = ImStb::STB_TEXTEDIT_GETCHAR(state, first_diff + i);
}

// As InputText() retain textual data and we currently provide a path for user to not retain it (via local variables)
// we need some form of hook to reapply data back to user buffer on deactivation frame. (#4714)
// It would be more desirable that we discourage users from taking advantage of the "user not retaining data" trick,
// but that more likely be attractive when we do have _NoLiveEdit flag available.
void SegaUi::InputTextDeactivateHook(SegaUiID id)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiInputTextState* state = &g.InputTextState;
    if (id == 0 || state->ID != id)
        return;
    g.InputTextDeactivatedState.ID = state->ID;
    g.InputTextDeactivatedState.TextA.resize(state->CurLenA + 1);
    memcpy(g.InputTextDeactivatedState.TextA.Data, state->TextA.Data ? state->TextA.Data : "", state->CurLenA + 1);
}

struct input_state
{
    ImVec4 background, icon, outline;
    float slow, line;
};

bool SegaUi::InputTextEx(const char* label, const char* hint, char* buf, int buf_size, const ImVec2& size_arg, SegaUiInputTextFlags flags, SegaUiInputTextCallback callback, void* callback_user_data)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    IM_ASSERT(buf != NULL && buf_size >= 0);
    IM_ASSERT(!((flags & SegaUiInputTextFlags_CallbackHistory) && (flags & SegaUiInputTextFlags_Multiline)));        // Can't use both together (they both use up/down keys)
    IM_ASSERT(!((flags & SegaUiInputTextFlags_CallbackCompletion) && (flags & SegaUiInputTextFlags_AllowTabInput))); // Can't use both together (they both use tab key)

    SegaUiContext& g = *GSegaUi;
    SegaUiIO& io = g.IO;
    const SegaUiStyle& style = g.Style;

    const bool RENDER_SELECTION_WHEN_INACTIVE = false;
    const bool is_multiline = (flags & SegaUiInputTextFlags_Multiline) != 0;
    const bool is_readonly = (flags & SegaUiInputTextFlags_ReadOnly) != 0;
    const bool is_password = (flags & SegaUiInputTextFlags_Password) != 0;
    const bool is_undoable = (flags & SegaUiInputTextFlags_NoUndoRedo) == 0;
    const bool is_resizable = (flags & SegaUiInputTextFlags_CallbackResize) != 0;
    if (is_resizable)
        IM_ASSERT(callback != NULL); // Must provide a callback if you set the SegaUiInputTextFlags_CallbackResize flag!

    if (is_multiline) // Open group before calling GetID() because groups tracks id created within their scope (including the scrollbar)
        BeginGroup();
    const SegaUiID id = window->GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const ImVec2 frame_size = CalcItemSize(size_arg, CalcItemWidth(), (is_multiline ? g.FontSize * 8.0f : label_size.y) + style.FramePadding.y * 2.0f); // Arbitrary default of 8 lines high for multi-line
    const ImVec2 total_size = ImVec2(frame_size.x + (label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f), frame_size.y);

    const ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + frame_size);
    const ImRect total_bb(frame_bb.Min, frame_bb.Min + total_size);

    SegaUiWindow* draw_window = window;
    ImVec2 inner_size = frame_size;
    SegaUiItemStatusFlags item_status_flags = 0;
    SegaUiLastItemData item_data_backup;
    if (is_multiline)
    {
        ImVec2 backup_pos = window->DC.CursorPos;
        ItemSize(total_bb, style.FramePadding.y);
        if (!ItemAdd(total_bb, id, &frame_bb, SegaUiItemFlags_Inputable))
        {
            EndGroup();
            return false;
        }
        item_status_flags = g.LastItemData.StatusFlags;
        item_data_backup = g.LastItemData;
        window->DC.CursorPos = backup_pos;

        // We reproduce the contents of BeginChildFrame() in order to provide 'label' so our window internal data are easier to read/debug.
        // FIXME-NAV: Pressing NavActivate will trigger general child activation right before triggering our own below. Harmless but bizarre.
        PushStyleColor(SegaUiCol_ChildBg, style.Colors[SegaUiCol_FrameBg]);
        PushStyleVar(SegaUiStyleVar_ChildRounding, style.FrameRounding);
        PushStyleVar(SegaUiStyleVar_ChildBorderSize, style.FrameBorderSize);
        PushStyleVar(SegaUiStyleVar_WindowPadding, ImVec2(0, 0)); // Ensure no clip rect so mouse hover can reach FramePadding edges
        bool child_visible = BeginChildEx(label, id, frame_bb.GetSize(), true, SegaUiWindowFlags_NoMove);
        PopStyleVar(3);
        PopStyleColor();
        if (!child_visible)
        {
            EndChild();
            EndGroup();
            return false;
        }
        draw_window = g.CurrentWindow; // Child window
        draw_window->DC.NavLayersActiveMaskNext |= (1 << draw_window->DC.NavLayerCurrent); // This is to ensure that EndChild() will display a navigation highlight so we can "enter" into it.
        draw_window->DC.CursorPos += style.FramePadding;
        inner_size.x -= draw_window->ScrollbarSizes.x;
    }
    else
    {
        // Support for internal SegaUiInputTextFlags_MergedItem flag, which could be redesigned as an ItemFlags if needed (with test performed in ItemAdd)
        ItemSize(total_bb, style.FramePadding.y);
        if (!(flags & SegaUiInputTextFlags_MergedItem))
            if (!ItemAdd(total_bb, id, &frame_bb, SegaUiItemFlags_Inputable))
                return false;
        item_status_flags = g.LastItemData.StatusFlags;
    }
    const bool hovered = ItemHoverable(frame_bb, id);
    if (hovered)
        g.MouseCursor = SegaUiMouseCursor_TextInput;

    // We are only allowed to access the state if we are already the active widget.
    SegaUiInputTextState* state = GetInputTextState(id);

    const bool input_requested_by_tabbing = (item_status_flags & SegaUiItemStatusFlags_FocusedByTabbing) != 0;
    const bool input_requested_by_nav = (g.ActiveId != id) && ((g.NavActivateId == id) && ((g.NavActivateFlags & SegaUiActivateFlags_PreferInput) || (g.NavInputSource == SegaUiInputSource_Keyboard)));

    const bool user_clicked = hovered && io.MouseClicked[0];
    const bool user_scroll_finish = is_multiline && state != NULL && g.ActiveId == 0 && g.ActiveIdPreviousFrame == GetWindowScrollbarID(draw_window, SegaUiAxis_Y);
    const bool user_scroll_active = is_multiline && state != NULL && g.ActiveId == GetWindowScrollbarID(draw_window, SegaUiAxis_Y);
    bool clear_active_id = false;
    bool select_all = false;

    float scroll_y = is_multiline ? draw_window->Scroll.y : FLT_MAX;

    const bool init_changed_specs = (state != NULL && state->Stb.single_line != !is_multiline); // state != NULL means its our state.
    const bool init_make_active = (user_clicked || user_scroll_finish || input_requested_by_nav || input_requested_by_tabbing);
    const bool init_state = (init_make_active || user_scroll_active);
    if ((init_state && g.ActiveId != id) || init_changed_specs)
    {
        // Access state even if we don't own it yet.
        state = &g.InputTextState;
        state->CursorAnimReset();

        // Backup state of deactivating item so they'll have a chance to do a write to output buffer on the same frame they report IsItemDeactivatedAfterEdit (#4714)
        InputTextDeactivateHook(state->ID);

        // Take a copy of the initial buffer value (both in original UTF-8 format and converted to wchar)
        // From the moment we focused we are ignoring the content of 'buf' (unless we are in read-only mode)
        const int buf_len = (int)strlen(buf);
        state->InitialTextA.resize(buf_len + 1);    // UTF-8. we use +1 to make sure that .Data is always pointing to at least an empty string.
        memcpy(state->InitialTextA.Data, buf, buf_len + 1);

        // Preserve cursor position and undo/redo stack if we come back to same widget
        // FIXME: Since we reworked this on 2022/06, may want to differenciate recycle_cursor vs recycle_undostate?
        bool recycle_state = (state->ID == id && !init_changed_specs);
        if (recycle_state && (state->CurLenA != buf_len || (state->TextAIsValid && strncmp(state->TextA.Data, buf, buf_len) != 0)))
            recycle_state = false;

        // Start edition
        const char* buf_end = NULL;
        state->ID = id;
        state->TextW.resize(buf_size + 1);          // wchar count <= UTF-8 count. we use +1 to make sure that .Data is always pointing to at least an empty string.
        state->TextA.resize(0);
        state->TextAIsValid = false;                // TextA is not valid yet (we will display buf until then)
        state->CurLenW = ImTextStrFromUtf8(state->TextW.Data, buf_size, buf, NULL, &buf_end);
        state->CurLenA = (int)(buf_end - buf);      // We can't get the result from ImStrncpy() above because it is not UTF-8 aware. Here we'll cut off malformed UTF-8.

        if (recycle_state)
        {
            // Recycle existing cursor/selection/undo stack but clamp position
            // Note a single mouse click will override the cursor/position immediately by calling stb_textedit_click handler.
            state->CursorClamp();
        }
        else
        {
            state->ScrollX = 0.0f;
            stb_textedit_initialize_state(&state->Stb, !is_multiline);
        }

        if (!is_multiline)
        {
            if (flags & SegaUiInputTextFlags_AutoSelectAll)
                select_all = true;
            if (input_requested_by_nav && (!recycle_state || !(g.NavActivateFlags & SegaUiActivateFlags_TryToPreserveState)))
                select_all = true;
            if (input_requested_by_tabbing || (user_clicked && io.KeyCtrl))
                select_all = true;
        }

        if (flags & SegaUiInputTextFlags_AlwaysOverwrite)
            state->Stb.insert_mode = 1; // stb field name is indeed incorrect (see #2863)
    }

    const bool is_osx = io.ConfigMacOSXBehaviors;
    if (g.ActiveId != id && init_make_active)
    {
        IM_ASSERT(state && state->ID == id);
        SetActiveID(id, window);
        SetFocusID(id, window);
        FocusWindow(window);
    }
    if (g.ActiveId == id)
    {
        // Declare some inputs, the other are registered and polled via Shortcut() routing system.
        if (user_clicked)
            SetKeyOwner(SegaUiKey_MouseLeft, id);
        g.ActiveIdUsingNavDirMask |= (1 << SegaUiDir_Left) | (1 << SegaUiDir_Right);
        if (is_multiline || (flags & SegaUiInputTextFlags_CallbackHistory))
            g.ActiveIdUsingNavDirMask |= (1 << SegaUiDir_Up) | (1 << SegaUiDir_Down);
        SetKeyOwner(SegaUiKey_Home, id);
        SetKeyOwner(SegaUiKey_End, id);
        if (is_multiline)
        {
            SetKeyOwner(SegaUiKey_PageUp, id);
            SetKeyOwner(SegaUiKey_PageDown, id);
        }
        if (is_osx)
            SetKeyOwner(SegaUiMod_Alt, id);
        if (flags & (SegaUiInputTextFlags_CallbackCompletion | SegaUiInputTextFlags_AllowTabInput)) // Disable keyboard tabbing out as we will use the \t character.
            SetShortcutRouting(SegaUiKey_Tab, id);
    }

    // We have an edge case if ActiveId was set through another widget (e.g. widget being swapped), clear id immediately (don't wait until the end of the function)
    if (g.ActiveId == id && state == NULL)
        ClearActiveID();

    // Release focus when we click outside
    if (g.ActiveId == id && io.MouseClicked[0] && !init_state && !init_make_active) //-V560
        clear_active_id = true;

    // Lock the decision of whether we are going to take the path displaying the cursor or selection
    bool render_cursor = (g.ActiveId == id) || (state && user_scroll_active);
    bool render_selection = state && (state->HasSelection() || select_all) && (RENDER_SELECTION_WHEN_INACTIVE || render_cursor);
    bool value_changed = false;
    bool validated = false;

    // When read-only we always use the live data passed to the function
    // FIXME-OPT: Because our selection/cursor code currently needs the wide text we need to convert it when active, which is not ideal :(
    if (is_readonly && state != NULL && (render_cursor || render_selection))
    {
        const char* buf_end = NULL;
        state->TextW.resize(buf_size + 1);
        state->CurLenW = ImTextStrFromUtf8(state->TextW.Data, state->TextW.Size, buf, NULL, &buf_end);
        state->CurLenA = (int)(buf_end - buf);
        state->CursorClamp();
        render_selection &= state->HasSelection();
    }

    // Select the buffer to render.
    const bool buf_display_from_state = (render_cursor || render_selection || g.ActiveId == id) && !is_readonly && state && state->TextAIsValid;
    const bool is_displaying_hint = (hint != NULL && (buf_display_from_state ? state->TextA.Data : buf)[0] == 0);

    // Password pushes a temporary font with only a fallback glyph
    if (is_password && !is_displaying_hint)
    {
        const ImFontGlyph* glyph = g.Font->FindGlyph('*');
        ImFont* password_font = &g.InputTextPasswordFont;
        password_font->FontSize = g.Font->FontSize;
        password_font->Scale = g.Font->Scale;
        password_font->Ascent = g.Font->Ascent;
        password_font->Descent = g.Font->Descent;
        password_font->ContainerAtlas = g.Font->ContainerAtlas;
        password_font->FallbackGlyph = glyph;
        password_font->FallbackAdvanceX = glyph->AdvanceX;
        IM_ASSERT(password_font->Glyphs.empty() && password_font->IndexAdvanceX.empty() && password_font->IndexLookup.empty());
        PushFont(password_font);
    }

    // Process mouse inputs and character inputs
    int backup_current_text_length = 0;
    if (g.ActiveId == id)
    {
        IM_ASSERT(state != NULL);
        backup_current_text_length = state->CurLenA;
        state->Edited = false;
        state->BufCapacityA = buf_size;
        state->Flags = flags;

        // Although we are active we don't prevent mouse from hovering other elements unless we are interacting right now with the widget.
        // Down the line we should have a cleaner library-wide concept of Selected vs Active.
        g.ActiveIdAllowOverlap = !io.MouseDown[0];

        // Edit in progress
        const float mouse_x = (io.MousePos.x - frame_bb.Min.x - style.FramePadding.x) + state->ScrollX;
        const float mouse_y = (is_multiline ? (io.MousePos.y - draw_window->DC.CursorPos.y) : (g.FontSize * 0.5f));

        if (select_all)
        {
            state->SelectAll();
            state->SelectedAllMouseLock = true;
        }
        else if (hovered && io.MouseClickedCount[0] >= 2 && !io.KeyShift)
        {
            stb_textedit_click(state, &state->Stb, mouse_x, mouse_y);
            const int multiclick_count = (io.MouseClickedCount[0] - 2);
            if ((multiclick_count % 2) == 0)
            {
                // Double-click: Select word
                // We always use the "Mac" word advance for double-click select vs CTRL+Right which use the platform dependent variant:
                // FIXME: There are likely many ways to improve this behavior, but there's no "right" behavior (depends on use-case, software, OS)
                const bool is_bol = (state->Stb.cursor == 0) || ImStb::STB_TEXTEDIT_GETCHAR(state, state->Stb.cursor - 1) == '\n';
                if (STB_TEXT_HAS_SELECTION(&state->Stb) || !is_bol)
                    state->OnKeyPressed(STB_TEXTEDIT_K_WORDLEFT);
                //state->OnKeyPressed(STB_TEXTEDIT_K_WORDRIGHT | STB_TEXTEDIT_K_SHIFT);
                if (!STB_TEXT_HAS_SELECTION(&state->Stb))
                    ImStb::stb_textedit_prep_selection_at_cursor(&state->Stb);
                state->Stb.cursor = ImStb::STB_TEXTEDIT_MOVEWORDRIGHT_MAC(state, state->Stb.cursor);
                state->Stb.select_end = state->Stb.cursor;
                ImStb::stb_textedit_clamp(state, &state->Stb);
            }
            else
            {
                // Triple-click: Select line
                const bool is_eol = ImStb::STB_TEXTEDIT_GETCHAR(state, state->Stb.cursor) == '\n';
                state->OnKeyPressed(STB_TEXTEDIT_K_LINESTART);
                state->OnKeyPressed(STB_TEXTEDIT_K_LINEEND | STB_TEXTEDIT_K_SHIFT);
                state->OnKeyPressed(STB_TEXTEDIT_K_RIGHT | STB_TEXTEDIT_K_SHIFT);
                if (!is_eol && is_multiline)
                {
                    ImSwap(state->Stb.select_start, state->Stb.select_end);
                    state->Stb.cursor = state->Stb.select_end;
                }
                state->CursorFollow = false;
            }
            state->CursorAnimReset();
        }
        else if (io.MouseClicked[0] && !state->SelectedAllMouseLock)
        {
            if (hovered)
            {
                if (io.KeyShift)
                    stb_textedit_drag(state, &state->Stb, mouse_x, mouse_y);
                else
                    stb_textedit_click(state, &state->Stb, mouse_x, mouse_y);
                state->CursorAnimReset();
            }
        }
        else if (io.MouseDown[0] && !state->SelectedAllMouseLock && (io.MouseDelta.x != 0.0f || io.MouseDelta.y != 0.0f))
        {
            stb_textedit_drag(state, &state->Stb, mouse_x, mouse_y);
            state->CursorAnimReset();
            state->CursorFollow = true;
        }
        if (state->SelectedAllMouseLock && !io.MouseDown[0])
            state->SelectedAllMouseLock = false;

        // We expect backends to emit a Tab key but some also emit a Tab character which we ignore (#2467, #1336)
        // (For Tab and Enter: Win32/SFML/Allegro are sending both keys and chars, GLFW and SDL are only sending keys. For Space they all send all threes)
        if ((flags & SegaUiInputTextFlags_AllowTabInput) && Shortcut(SegaUiKey_Tab, id) && !is_readonly)
        {
            unsigned int c = '\t'; // Insert TAB
            if (InputTextFilterCharacter(&c, flags, callback, callback_user_data, SegaUiInputSource_Keyboard))
                state->OnKeyPressed((int)c);
        }

        // Process regular text input (before we check for Return because using some IME will effectively send a Return?)
        // We ignore CTRL inputs, but need to allow ALT+CTRL as some keyboards (e.g. German) use AltGR (which _is_ Alt+Ctrl) to input certain characters.
        const bool ignore_char_inputs = (io.KeyCtrl && !io.KeyAlt) || (is_osx && io.KeySuper);
        if (io.InputQueueCharacters.Size > 0)
        {
            if (!ignore_char_inputs && !is_readonly && !input_requested_by_nav)
                for (int n = 0; n < io.InputQueueCharacters.Size; n++)
                {
                    // Insert character if they pass filtering
                    unsigned int c = (unsigned int)io.InputQueueCharacters[n];
                    if (c == '\t') // Skip Tab, see above.
                        continue;
                    if (InputTextFilterCharacter(&c, flags, callback, callback_user_data, SegaUiInputSource_Keyboard))
                        state->OnKeyPressed((int)c);
                }

            // Consume characters
            io.InputQueueCharacters.resize(0);
        }
    }

    // Process other shortcuts/key-presses
    bool revert_edit = false;
    if (g.ActiveId == id && !g.ActiveIdIsJustActivated && !clear_active_id)
    {
        IM_ASSERT(state != NULL);

        const int row_count_per_page = ImMax((int)((inner_size.y - style.FramePadding.y) / g.FontSize), 1);
        state->Stb.row_count_per_page = row_count_per_page;

        const int k_mask = (io.KeyShift ? STB_TEXTEDIT_K_SHIFT : 0);
        const bool is_wordmove_key_down = is_osx ? io.KeyAlt : io.KeyCtrl;                     // OS X style: Text editing cursor movement using Alt instead of Ctrl
        const bool is_startend_key_down = is_osx && io.KeySuper && !io.KeyCtrl && !io.KeyAlt;  // OS X style: Line/Text Start and End using Cmd+Arrows instead of Home/End

        // Using Shortcut() with SegaUiInputFlags_RouteFocused (default policy) to allow routing operations for other code (e.g. calling window trying to use CTRL+A and CTRL+B: formet would be handled by InputText)
        // Otherwise we could simply assume that we own the keys as we are active.
        const SegaUiInputFlags f_repeat = SegaUiInputFlags_Repeat;
        const bool is_cut = (Shortcut(SegaUiMod_Shortcut | SegaUiKey_X, id, f_repeat) || Shortcut(SegaUiMod_Shift | SegaUiKey_Delete, id, f_repeat)) && !is_readonly && !is_password && (!is_multiline || state->HasSelection());
        const bool is_copy = (Shortcut(SegaUiMod_Shortcut | SegaUiKey_C, id) || Shortcut(SegaUiMod_Ctrl | SegaUiKey_Insert, id)) && !is_password && (!is_multiline || state->HasSelection());
        const bool is_paste = (Shortcut(SegaUiMod_Shortcut | SegaUiKey_V, id, f_repeat) || Shortcut(SegaUiMod_Shift | SegaUiKey_Insert, id, f_repeat)) && !is_readonly;
        const bool is_undo = (Shortcut(SegaUiMod_Shortcut | SegaUiKey_Z, id, f_repeat)) && !is_readonly && is_undoable;
        const bool is_redo = (Shortcut(SegaUiMod_Shortcut | SegaUiKey_Y, id, f_repeat) || (is_osx && Shortcut(SegaUiMod_Shortcut | SegaUiMod_Shift | SegaUiKey_Z, id, f_repeat))) && !is_readonly && is_undoable;
        const bool is_select_all = Shortcut(SegaUiMod_Shortcut | SegaUiKey_A, id);

        // We allow validate/cancel with Nav source (gamepad) to makes it easier to undo an accidental NavInput press with no keyboard wired, but otherwise it isn't very useful.
        const bool nav_gamepad_active = (io.ConfigFlags & SegaUiConfigFlags_NavEnableGamepad) != 0 && (io.BackendFlags & SegaUiBackendFlags_HasGamepad) != 0;
        const bool is_enter_pressed = IsKeyPressed(SegaUiKey_Enter, true) || IsKeyPressed(SegaUiKey_KeypadEnter, true);
        const bool is_gamepad_validate = nav_gamepad_active && (IsKeyPressed(SegaUiKey_NavGamepadActivate, false) || IsKeyPressed(SegaUiKey_NavGamepadInput, false));
        const bool is_cancel = Shortcut(SegaUiKey_Escape, id, f_repeat) || (nav_gamepad_active && Shortcut(SegaUiKey_NavGamepadCancel, id, f_repeat));

        // FIXME: Should use more Shortcut() and reduce IsKeyPressed()+SetKeyOwner(), but requires modifiers combination to be taken account of.
        if (IsKeyPressed(SegaUiKey_LeftArrow)) { state->OnKeyPressed((is_startend_key_down ? STB_TEXTEDIT_K_LINESTART : is_wordmove_key_down ? STB_TEXTEDIT_K_WORDLEFT : STB_TEXTEDIT_K_LEFT) | k_mask); }
        else if (IsKeyPressed(SegaUiKey_RightArrow)) { state->OnKeyPressed((is_startend_key_down ? STB_TEXTEDIT_K_LINEEND : is_wordmove_key_down ? STB_TEXTEDIT_K_WORDRIGHT : STB_TEXTEDIT_K_RIGHT) | k_mask); }
        else if (IsKeyPressed(SegaUiKey_UpArrow) && is_multiline) { if (io.KeyCtrl) SetScrollY(draw_window, ImMax(draw_window->Scroll.y - g.FontSize, 0.0f)); else state->OnKeyPressed((is_startend_key_down ? STB_TEXTEDIT_K_TEXTSTART : STB_TEXTEDIT_K_UP) | k_mask); }
        else if (IsKeyPressed(SegaUiKey_DownArrow) && is_multiline) { if (io.KeyCtrl) SetScrollY(draw_window, ImMin(draw_window->Scroll.y + g.FontSize, GetScrollMaxY())); else state->OnKeyPressed((is_startend_key_down ? STB_TEXTEDIT_K_TEXTEND : STB_TEXTEDIT_K_DOWN) | k_mask); }
        else if (IsKeyPressed(SegaUiKey_PageUp) && is_multiline) { state->OnKeyPressed(STB_TEXTEDIT_K_PGUP | k_mask); scroll_y -= row_count_per_page * g.FontSize; }
        else if (IsKeyPressed(SegaUiKey_PageDown) && is_multiline) { state->OnKeyPressed(STB_TEXTEDIT_K_PGDOWN | k_mask); scroll_y += row_count_per_page * g.FontSize; }
        else if (IsKeyPressed(SegaUiKey_Home)) { state->OnKeyPressed(io.KeyCtrl ? STB_TEXTEDIT_K_TEXTSTART | k_mask : STB_TEXTEDIT_K_LINESTART | k_mask); }
        else if (IsKeyPressed(SegaUiKey_End)) { state->OnKeyPressed(io.KeyCtrl ? STB_TEXTEDIT_K_TEXTEND | k_mask : STB_TEXTEDIT_K_LINEEND | k_mask); }
        else if (IsKeyPressed(SegaUiKey_Delete) && !is_readonly && !is_cut)
        {
            if (!state->HasSelection())
            {
                // OSX doesn't seem to have Super+Delete to delete until end-of-line, so we don't emulate that (as opposed to Super+Backspace)
                if (is_wordmove_key_down)
                    state->OnKeyPressed(STB_TEXTEDIT_K_WORDRIGHT | STB_TEXTEDIT_K_SHIFT);
            }
            state->OnKeyPressed(STB_TEXTEDIT_K_DELETE | k_mask);
        }
        else if (IsKeyPressed(SegaUiKey_Backspace) && !is_readonly)
        {
            if (!state->HasSelection())
            {
                if (is_wordmove_key_down)
                    state->OnKeyPressed(STB_TEXTEDIT_K_WORDLEFT | STB_TEXTEDIT_K_SHIFT);
                else if (is_osx && io.KeySuper && !io.KeyAlt && !io.KeyCtrl)
                    state->OnKeyPressed(STB_TEXTEDIT_K_LINESTART | STB_TEXTEDIT_K_SHIFT);
            }
            state->OnKeyPressed(STB_TEXTEDIT_K_BACKSPACE | k_mask);
        }
        else if (is_enter_pressed || is_gamepad_validate)
        {
            // Determine if we turn Enter into a \n character
            bool ctrl_enter_for_new_line = (flags & SegaUiInputTextFlags_CtrlEnterForNewLine) != 0;
            if (!is_multiline || is_gamepad_validate || (ctrl_enter_for_new_line && !io.KeyCtrl) || (!ctrl_enter_for_new_line && io.KeyCtrl))
            {
                validated = true;
                if (io.ConfigInputTextEnterKeepActive && !is_multiline)
                    state->SelectAll(); // No need to scroll
                else
                    clear_active_id = true;
            }
            else if (!is_readonly)
            {
                unsigned int c = '\n'; // Insert new line
                if (InputTextFilterCharacter(&c, flags, callback, callback_user_data, SegaUiInputSource_Keyboard))
                    state->OnKeyPressed((int)c);
            }
        }
        else if (is_cancel)
        {
            if (flags & SegaUiInputTextFlags_EscapeClearsAll)
            {
                if (state->CurLenA > 0)
                {
                    revert_edit = true;
                }
                else
                {
                    render_cursor = render_selection = false;
                    clear_active_id = true;
                }
            }
            else
            {
                clear_active_id = revert_edit = true;
                render_cursor = render_selection = false;
            }
        }
        else if (is_undo || is_redo)
        {
            state->OnKeyPressed(is_undo ? STB_TEXTEDIT_K_UNDO : STB_TEXTEDIT_K_REDO);
            state->ClearSelection();
        }
        else if (is_select_all)
        {
            state->SelectAll();
            state->CursorFollow = true;
        }
        else if (is_cut || is_copy)
        {
            // Cut, Copy
            if (io.SetClipboardTextFn)
            {
                const int ib = state->HasSelection() ? ImMin(state->Stb.select_start, state->Stb.select_end) : 0;
                const int ie = state->HasSelection() ? ImMax(state->Stb.select_start, state->Stb.select_end) : state->CurLenW;
                const int clipboard_data_len = ImTextCountUtf8BytesFromStr(state->TextW.Data + ib, state->TextW.Data + ie) + 1;
                char* clipboard_data = (char*)IM_ALLOC(clipboard_data_len * sizeof(char));
                ImTextStrToUtf8(clipboard_data, clipboard_data_len, state->TextW.Data + ib, state->TextW.Data + ie);
                SetClipboardText(clipboard_data);
                MemFree(clipboard_data);
            }
            if (is_cut)
            {
                if (!state->HasSelection())
                    state->SelectAll();
                state->CursorFollow = true;
                stb_textedit_cut(state, &state->Stb);
            }
        }
        else if (is_paste)
        {
            if (const char* clipboard = GetClipboardText())
            {
                // Filter pasted buffer
                const int clipboard_len = (int)strlen(clipboard);
                ImWchar* clipboard_filtered = (ImWchar*)IM_ALLOC((clipboard_len + 1) * sizeof(ImWchar));
                int clipboard_filtered_len = 0;
                for (const char* s = clipboard; *s != 0; )
                {
                    unsigned int c;
                    s += ImTextCharFromUtf8(&c, s, NULL);
                    if (!InputTextFilterCharacter(&c, flags, callback, callback_user_data, SegaUiInputSource_Clipboard))
                        continue;
                    clipboard_filtered[clipboard_filtered_len++] = (ImWchar)c;
                }
                clipboard_filtered[clipboard_filtered_len] = 0;
                if (clipboard_filtered_len > 0) // If everything was filtered, ignore the pasting operation
                {
                    stb_textedit_paste(state, &state->Stb, clipboard_filtered, clipboard_filtered_len);
                    state->CursorFollow = true;
                }
                MemFree(clipboard_filtered);
            }
        }

        // Update render selection flag after events have been handled, so selection highlight can be displayed during the same frame.
        render_selection |= state->HasSelection() && (RENDER_SELECTION_WHEN_INACTIVE || render_cursor);
    }

    // Process callbacks and apply result back to user's buffer.
    const char* apply_new_text = NULL;
    int apply_new_text_length = 0;
    if (g.ActiveId == id)
    {
        IM_ASSERT(state != NULL);
        if (revert_edit && !is_readonly)
        {
            if (flags & SegaUiInputTextFlags_EscapeClearsAll)
            {
                // Clear input
                apply_new_text = "";
                apply_new_text_length = 0;
                STB_TEXTEDIT_CHARTYPE empty_string;
                stb_textedit_replace(state, &state->Stb, &empty_string, 0);
            }
            else if (strcmp(buf, state->InitialTextA.Data) != 0)
            {
                // Restore initial value. Only return true if restoring to the initial value changes the current buffer contents.
                // Push records into the undo stack so we can CTRL+Z the revert operation itself
                apply_new_text = state->InitialTextA.Data;
                apply_new_text_length = state->InitialTextA.Size - 1;
                value_changed = true;
                ImVector<ImWchar> w_text;
                if (apply_new_text_length > 0)
                {
                    w_text.resize(ImTextCountCharsFromUtf8(apply_new_text, apply_new_text + apply_new_text_length) + 1);
                    ImTextStrFromUtf8(w_text.Data, w_text.Size, apply_new_text, apply_new_text + apply_new_text_length);
                }
                stb_textedit_replace(state, &state->Stb, w_text.Data, (apply_new_text_length > 0) ? (w_text.Size - 1) : 0);
            }
        }

        // Apply ASCII value
        if (!is_readonly)
        {
            state->TextAIsValid = true;
            state->TextA.resize(state->TextW.Size * 4 + 1);
            ImTextStrToUtf8(state->TextA.Data, state->TextA.Size, state->TextW.Data, NULL);
        }

        // When using 'SegaUiInputTextFlags_EnterReturnsTrue' as a special case we reapply the live buffer back to the input buffer before clearing ActiveId, even though strictly speaking it wasn't modified on this frame.
        // If we didn't do that, code like InputInt() with SegaUiInputTextFlags_EnterReturnsTrue would fail.
        // This also allows the user to use InputText() with SegaUiInputTextFlags_EnterReturnsTrue without maintaining any user-side storage (please note that if you use this property along SegaUiInputTextFlags_CallbackResize you can end up with your temporary string object unnecessarily allocating once a frame, either store your string data, either if you don't then don't use SegaUiInputTextFlags_CallbackResize).
        const bool apply_edit_back_to_user_buffer = !revert_edit || (validated && (flags & SegaUiInputTextFlags_EnterReturnsTrue) != 0);
        if (apply_edit_back_to_user_buffer)
        {
            // Apply new value immediately - copy modified buffer back
            // Note that as soon as the input box is active, the in-widget value gets priority over any underlying modification of the input buffer
            // FIXME: We actually always render 'buf' when calling DrawList->AddText, making the comment above incorrect.
            // FIXME-OPT: CPU waste to do this every time the widget is active, should mark dirty state from the stb_textedit callbacks.

            // User callback
            if ((flags & (SegaUiInputTextFlags_CallbackCompletion | SegaUiInputTextFlags_CallbackHistory | SegaUiInputTextFlags_CallbackEdit | SegaUiInputTextFlags_CallbackAlways)) != 0)
            {
                IM_ASSERT(callback != NULL);

                // The reason we specify the usage semantic (Completion/History) is that Completion needs to disable keyboard TABBING at the moment.
                SegaUiInputTextFlags event_flag = 0;
                SegaUiKey event_key = SegaUiKey_None;
                if ((flags & SegaUiInputTextFlags_CallbackCompletion) != 0 && Shortcut(SegaUiKey_Tab, id))
                {
                    event_flag = SegaUiInputTextFlags_CallbackCompletion;
                    event_key = SegaUiKey_Tab;
                }
                else if ((flags & SegaUiInputTextFlags_CallbackHistory) != 0 && IsKeyPressed(SegaUiKey_UpArrow))
                {
                    event_flag = SegaUiInputTextFlags_CallbackHistory;
                    event_key = SegaUiKey_UpArrow;
                }
                else if ((flags & SegaUiInputTextFlags_CallbackHistory) != 0 && IsKeyPressed(SegaUiKey_DownArrow))
                {
                    event_flag = SegaUiInputTextFlags_CallbackHistory;
                    event_key = SegaUiKey_DownArrow;
                }
                else if ((flags & SegaUiInputTextFlags_CallbackEdit) && state->Edited)
                {
                    event_flag = SegaUiInputTextFlags_CallbackEdit;
                }
                else if (flags & SegaUiInputTextFlags_CallbackAlways)
                {
                    event_flag = SegaUiInputTextFlags_CallbackAlways;
                }

                if (event_flag)
                {
                    SegaUiInputTextCallbackData callback_data;
                    callback_data.Ctx = &g;
                    callback_data.EventFlag = event_flag;
                    callback_data.Flags = flags;
                    callback_data.UserData = callback_user_data;

                    char* callback_buf = is_readonly ? buf : state->TextA.Data;
                    callback_data.EventKey = event_key;
                    callback_data.Buf = callback_buf;
                    callback_data.BufTextLen = state->CurLenA;
                    callback_data.BufSize = state->BufCapacityA;
                    callback_data.BufDirty = false;

                    // We have to convert from wchar-positions to UTF-8-positions, which can be pretty slow (an incentive to ditch the ImWchar buffer, see https://github.com/nothings/stb/issues/188)
                    ImWchar* text = state->TextW.Data;
                    const int utf8_cursor_pos = callback_data.CursorPos = ImTextCountUtf8BytesFromStr(text, text + state->Stb.cursor);
                    const int utf8_selection_start = callback_data.SelectionStart = ImTextCountUtf8BytesFromStr(text, text + state->Stb.select_start);
                    const int utf8_selection_end = callback_data.SelectionEnd = ImTextCountUtf8BytesFromStr(text, text + state->Stb.select_end);

                    // Call user code
                    callback(&callback_data);

                    // Read back what user may have modified
                    callback_buf = is_readonly ? buf : state->TextA.Data; // Pointer may have been invalidated by a resize callback
                    IM_ASSERT(callback_data.Buf == callback_buf);         // Invalid to modify those fields
                    IM_ASSERT(callback_data.BufSize == state->BufCapacityA);
                    IM_ASSERT(callback_data.Flags == flags);
                    const bool buf_dirty = callback_data.BufDirty;
                    if (callback_data.CursorPos != utf8_cursor_pos || buf_dirty) { state->Stb.cursor = ImTextCountCharsFromUtf8(callback_data.Buf, callback_data.Buf + callback_data.CursorPos); state->CursorFollow = true; }
                    if (callback_data.SelectionStart != utf8_selection_start || buf_dirty) { state->Stb.select_start = (callback_data.SelectionStart == callback_data.CursorPos) ? state->Stb.cursor : ImTextCountCharsFromUtf8(callback_data.Buf, callback_data.Buf + callback_data.SelectionStart); }
                    if (callback_data.SelectionEnd != utf8_selection_end || buf_dirty) { state->Stb.select_end = (callback_data.SelectionEnd == callback_data.SelectionStart) ? state->Stb.select_start : ImTextCountCharsFromUtf8(callback_data.Buf, callback_data.Buf + callback_data.SelectionEnd); }
                    if (buf_dirty)
                    {
                        IM_ASSERT((flags & SegaUiInputTextFlags_ReadOnly) == 0);
                        IM_ASSERT(callback_data.BufTextLen == (int)strlen(callback_data.Buf)); // You need to maintain BufTextLen if you change the text!
                        InputTextReconcileUndoStateAfterUserCallback(state, callback_data.Buf, callback_data.BufTextLen); // FIXME: Move the rest of this block inside function and rename to InputTextReconcileStateAfterUserCallback() ?
                        if (callback_data.BufTextLen > backup_current_text_length && is_resizable)
                            state->TextW.resize(state->TextW.Size + (callback_data.BufTextLen - backup_current_text_length)); // Worse case scenario resize
                        state->CurLenW = ImTextStrFromUtf8(state->TextW.Data, state->TextW.Size, callback_data.Buf, NULL);
                        state->CurLenA = callback_data.BufTextLen;  // Assume correct length and valid UTF-8 from user, saves us an extra strlen()
                        state->CursorAnimReset();
                    }
                }
            }

            // Will copy result string if modified
            if (!is_readonly && strcmp(state->TextA.Data, buf) != 0)
            {
                apply_new_text = state->TextA.Data;
                apply_new_text_length = state->CurLenA;
                value_changed = true;
            }
        }
    }

    // Handle reapplying final data on deactivation (see InputTextDeactivateHook() for details)
    if (g.InputTextDeactivatedState.ID == id)
    {
        if (g.ActiveId != id && IsItemDeactivatedAfterEdit() && !is_readonly)
        {
            apply_new_text = g.InputTextDeactivatedState.TextA.Data;
            apply_new_text_length = g.InputTextDeactivatedState.TextA.Size - 1;
            value_changed |= (strcmp(g.InputTextDeactivatedState.TextA.Data, buf) != 0);
            //SEGAUI_DEBUG_LOG("InputText(): apply Deactivated data for 0x%08X: \"%.*s\".\n", id, apply_new_text_length, apply_new_text);
        }
        g.InputTextDeactivatedState.ID = 0;
    }

    // Copy result to user buffer. This can currently only happen when (g.ActiveId == id)
    if (apply_new_text != NULL)
    {
        // We cannot test for 'backup_current_text_length != apply_new_text_length' here because we have no guarantee that the size
        // of our owned buffer matches the size of the string object held by the user, and by design we allow InputText() to be used
        // without any storage on user's side.
        IM_ASSERT(apply_new_text_length >= 0);
        if (is_resizable)
        {
            SegaUiInputTextCallbackData callback_data;
            callback_data.Ctx = &g;
            callback_data.EventFlag = SegaUiInputTextFlags_CallbackResize;
            callback_data.Flags = flags;
            callback_data.Buf = buf;
            callback_data.BufTextLen = apply_new_text_length;
            callback_data.BufSize = ImMax(buf_size, apply_new_text_length + 1);
            callback_data.UserData = callback_user_data;
            callback(&callback_data);
            buf = callback_data.Buf;
            buf_size = callback_data.BufSize;
            apply_new_text_length = ImMin(callback_data.BufTextLen, buf_size - 1);
            IM_ASSERT(apply_new_text_length <= buf_size);
        }
        //SEGAUI_DEBUG_PRINT("InputText(\"%s\"): apply_new_text length %d\n", label, apply_new_text_length);

        // If the underlying buffer resize was denied or not carried to the next frame, apply_new_text_length+1 may be >= buf_size.
        ImStrncpy(buf, apply_new_text, ImMin(apply_new_text_length + 1, buf_size));
    }

    // Release active ID at the end of the function (so e.g. pressing Return still does a final application of the value)
    // Otherwise request text input ahead for next frame.
    if (g.ActiveId == id && clear_active_id)
        ClearActiveID();
    else if (g.ActiveId == id)
        g.WantTextInputNextFrame = 1;

    static std::map<SegaUiID, input_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, input_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.background = ImLerp(it_anim->second.background, IsItemActive() ? c::input::background_active : c::input::background_inactive, g.IO.DeltaTime * 12.f);
    it_anim->second.icon = ImLerp(it_anim->second.icon, IsItemActive() ? c::accent : c::input::icon, g.IO.DeltaTime * 12.f);
    it_anim->second.outline = ImLerp(it_anim->second.outline, IsItemActive() ? c::accent : c::input::outline, g.IO.DeltaTime * 12.f);

    it_anim->second.line = ImLerp(it_anim->second.line, IsItemActive() ? 2.f : 0.f, g.IO.DeltaTime * 12.f);

    if (!is_multiline)
    {

        GetWindowDrawList()->AddRectFilled(frame_bb.Min, frame_bb.Max, GetColorU32(it_anim->second.outline), c::combo::rounding);

        invisible_shadow(1.f, frame_bb.Min, frame_bb.Max, GetColorU32(c::accent), 500);

        GetWindowDrawList()->AddRectFilled(frame_bb.Min + ImVec2(1, 1), frame_bb.Max - ImVec2(1, 1), GetColorU32(it_anim->second.background), c::input::rounding);

        //GetWindowDrawList()->AddImage(pic::input_widget, frame_bb.Min + ImVec2(size_arg.x - 30, (size_arg.y - 25) / 2), frame_bb.Max - ImVec2(5, (size_arg.y - 25) / 2), ImVec2(0, 0), ImVec2(1, 1), SegaUi::GetColorU32(it_anim->second.icon));


     //   GetWindowDrawList()->AddRectFilled(frame_bb.Min + ImVec2(size_arg.x - 30, (size_arg.y - 25) / 2), frame_bb.Max - ImVec2(5, (size_arg.y - 25) / 2), GetColorU32(c::accent), c::input::rounding);


    }

    const ImVec4 clip_rect(frame_bb.Min.x, frame_bb.Min.y, frame_bb.Min.x + inner_size.x - 35, frame_bb.Min.y + inner_size.y); // Not using frame_bb.Max because we have adjusted size
    ImVec2 draw_pos = is_multiline ? draw_window->DC.CursorPos : frame_bb.Min + ImVec2(10, (size_arg.y - CalcTextSize(hint).y) / 2);
    ImVec2 text_size(0.0f, 0.0f);

    // Set upper limit of single-line InputTextEx() at 2 million characters strings. The current pathological worst case is a long line
    // without any carriage return, which would makes ImFont::RenderText() reserve too many vertices and probably crash. Avoid it altogether.
    // Note that we only use this limit on single-line InputText(), so a pathologically large line on a InputTextMultiline() would still crash.
    const int buf_display_max_length = 2 * 1024 * 1024;
    const char* buf_display = buf_display_from_state ? state->TextA.Data : buf; //-V595
    const char* buf_display_end = NULL; // We have specialized paths below for setting the length
    if (is_displaying_hint)
    {
        buf_display = hint;
        buf_display_end = hint + strlen(hint);
    }

    // Render text. We currently only render selection when the widget is active or while scrolling.
    // FIXME: We could remove the '&& render_cursor' to keep rendering selection when inactive.
    if (render_cursor || render_selection)
    {
        IM_ASSERT(state != NULL);
        if (!is_displaying_hint)
            buf_display_end = buf_display + state->CurLenA;

        // Render text (with cursor and selection)
        // This is going to be messy. We need to:
        // - Display the text (this alone can be more easily clipped)
        // - Handle scrolling, highlight selection, display cursor (those all requires some form of 1d->2d cursor position calculation)
        // - Measure text height (for scrollbar)
        // We are attempting to do most of that in **one main pass** to minimize the computation cost (non-negligible for large amount of text) + 2nd pass for selection rendering (we could merge them by an extra refactoring effort)
        // FIXME: This should occur on buf_display but we'd need to maintain cursor/select_start/select_end for UTF-8.
        const ImWchar* text_begin = state->TextW.Data;
        ImVec2 cursor_offset, select_start_offset;

        {
            // Find lines numbers straddling 'cursor' (slot 0) and 'select_start' (slot 1) positions.
            const ImWchar* searches_input_ptr[2] = { NULL, NULL };
            int searches_result_line_no[2] = { -1000, -1000 };
            int searches_remaining = 0;
            if (render_cursor)
            {
                searches_input_ptr[0] = text_begin + state->Stb.cursor;
                searches_result_line_no[0] = -1;
                searches_remaining++;
            }
            if (render_selection)
            {
                searches_input_ptr[1] = text_begin + ImMin(state->Stb.select_start, state->Stb.select_end);
                searches_result_line_no[1] = -1;
                searches_remaining++;
            }

            // Iterate all lines to find our line numbers
            // In multi-line mode, we never exit the loop until all lines are counted, so add one extra to the searches_remaining counter.
            searches_remaining += is_multiline ? 1 : 0;
            int line_count = 0;
            //for (const ImWchar* s = text_begin; (s = (const ImWchar*)wcschr((const wchar_t*)s, (wchar_t)'\n')) != NULL; s++)  // FIXME-OPT: Could use this when wchar_t are 16-bit
            for (const ImWchar* s = text_begin; *s != 0; s++)
                if (*s == '\n')
                {
                    line_count++;
                    if (searches_result_line_no[0] == -1 && s >= searches_input_ptr[0]) { searches_result_line_no[0] = line_count; if (--searches_remaining <= 0) break; }
                    if (searches_result_line_no[1] == -1 && s >= searches_input_ptr[1]) { searches_result_line_no[1] = line_count; if (--searches_remaining <= 0) break; }
                }
            line_count++;
            if (searches_result_line_no[0] == -1)
                searches_result_line_no[0] = line_count;
            if (searches_result_line_no[1] == -1)
                searches_result_line_no[1] = line_count;

            // Calculate 2d position by finding the beginning of the line and measuring distance
            cursor_offset.x = InputTextCalcTextSizeW(&g, ImStrbolW(searches_input_ptr[0], text_begin), searches_input_ptr[0]).x;
            cursor_offset.y = searches_result_line_no[0] * g.FontSize;
            if (searches_result_line_no[1] >= 0)
            {
                select_start_offset.x = InputTextCalcTextSizeW(&g, ImStrbolW(searches_input_ptr[1], text_begin), searches_input_ptr[1]).x;
                select_start_offset.y = searches_result_line_no[1] * g.FontSize;
            }

            // Store text height (note that we haven't calculated text width at all, see GitHub issues #383, #1224)
            if (is_multiline)
                text_size = ImVec2(inner_size.x, line_count * g.FontSize);
        }

        // Scroll
        if (render_cursor && state->CursorFollow)
        {
            // Horizontal scroll in chunks of quarter width
            if (!(flags & SegaUiInputTextFlags_NoHorizontalScroll))
            {
                const float scroll_increment_x = inner_size.x * 0.25f;
                const float visible_width = inner_size.x - style.FramePadding.x;
                if (cursor_offset.x < state->ScrollX)
                    state->ScrollX = IM_FLOOR(ImMax(0.0f, cursor_offset.x - scroll_increment_x));
                else if (cursor_offset.x - visible_width >= state->ScrollX)
                    state->ScrollX = IM_FLOOR(cursor_offset.x - visible_width + scroll_increment_x);
            }
            else
            {
                state->ScrollX = 0.0f;
            }

            // Vertical scroll
            if (is_multiline)
            {
                // Test if cursor is vertically visible
                if (cursor_offset.y - g.FontSize < scroll_y)
                    scroll_y = ImMax(0.0f, cursor_offset.y - g.FontSize);
                else if (cursor_offset.y - (inner_size.y - style.FramePadding.y * 2.0f) >= scroll_y)
                    scroll_y = cursor_offset.y - inner_size.y + style.FramePadding.y * 2.0f;
                const float scroll_max_y = ImMax((text_size.y + style.FramePadding.y * 2.0f) - inner_size.y, 0.0f);
                scroll_y = ImClamp(scroll_y, 0.0f, scroll_max_y);
                draw_pos.y += (draw_window->Scroll.y - scroll_y);   // Manipulate cursor pos immediately avoid a frame of lag
                draw_window->Scroll.y = scroll_y;
            }

            state->CursorFollow = false;
        }

        // Draw selection
        const ImVec2 draw_scroll = ImVec2(state->ScrollX, 0.0f);
        if (render_selection)
        {
            const ImWchar* text_selected_begin = text_begin + ImMin(state->Stb.select_start, state->Stb.select_end);
            const ImWchar* text_selected_end = text_begin + ImMax(state->Stb.select_start, state->Stb.select_end);

            ImU32 bg_color = GetColorU32(SegaUiCol_TextSelectedBg, render_cursor ? 1.0f : 0.6f); // FIXME: current code flow mandate that render_cursor is always true here, we are leaving the transparent one for tests.
            float bg_offy_up = is_multiline ? 0.0f : -1.0f;    // FIXME: those offsets should be part of the style? they don't play so well with multi-line selection.
            float bg_offy_dn = is_multiline ? 0.0f : 2.0f;
            ImVec2 rect_pos = draw_pos + select_start_offset - draw_scroll;
            for (const ImWchar* p = text_selected_begin; p < text_selected_end; )
            {
                if (rect_pos.y > clip_rect.w + g.FontSize)
                    break;
                if (rect_pos.y < clip_rect.y)
                {
                    //p = (const ImWchar*)wmemchr((const wchar_t*)p, '\n', text_selected_end - p);  // FIXME-OPT: Could use this when wchar_t are 16-bit
                    //p = p ? p + 1 : text_selected_end;
                    while (p < text_selected_end)
                        if (*p++ == '\n')
                            break;
                }
                else
                {
                    ImVec2 rect_size = InputTextCalcTextSizeW(&g, p, text_selected_end, &p, NULL, true);
                    if (rect_size.x <= 0.0f) rect_size.x = IM_FLOOR(g.Font->GetCharAdvance((ImWchar)' ') * 0.50f); // So we can see selected empty lines
                    ImRect rect(rect_pos + ImVec2(0.0f, bg_offy_up - g.FontSize), rect_pos + ImVec2(rect_size.x, bg_offy_dn));
                    rect.ClipWith(clip_rect);
                    if (rect.Overlaps(clip_rect))
                        draw_window->DrawList->AddRectFilled(rect.Min, rect.Max, bg_color);
                }
                rect_pos.x = draw_pos.x - draw_scroll.x;
                rect_pos.y += g.FontSize;
            }
        }

        // We test for 'buf_display_max_length' as a way to avoid some pathological cases (e.g. single-line 1 MB string) which would make ImDrawList crash.
        if (is_multiline || (buf_display_end - buf_display) < buf_display_max_length)
        {
            ImU32 col = GetColorU32(is_displaying_hint ? c::text::text : c::text::text_active);
            draw_window->DrawList->AddText(g.Font, g.FontSize, draw_pos - draw_scroll, col, buf_display, buf_display_end, 0.0f, is_multiline ? NULL : &clip_rect);
        }

        // Draw blinking cursor
        if (render_cursor)
        {
            state->CursorAnim += io.DeltaTime;
            bool cursor_is_visible = (!g.IO.ConfigInputTextCursorBlink) || (state->CursorAnim <= 0.0f) || ImFmod(state->CursorAnim, 1.20f) <= 0.80f;
            ImVec2 cursor_screen_pos = ImFloor(draw_pos + cursor_offset - draw_scroll);
            ImRect cursor_screen_rect(cursor_screen_pos.x, cursor_screen_pos.y - g.FontSize + 0.5f, cursor_screen_pos.x + 1.0f, cursor_screen_pos.y - 1.5f);

            it_anim->second.slow = ImLerp(it_anim->second.slow, cursor_screen_rect.Min.x - total_bb.Min.x, g.IO.DeltaTime * 20.f);
            if (cursor_is_visible && cursor_screen_rect.Overlaps(clip_rect))
                draw_window->DrawList->AddLine(total_bb.Min + ImVec2(it_anim->second.slow, 11), total_bb.GetBL() - ImVec2(-it_anim->second.slow, 11), GetColorU32(c::text::text_active));

            // Notify OS of text input position for advanced IME (-1 x offset so that Windows IME can cover our cursor. Bit of an extra nicety.)
            if (!is_readonly)
            {
                g.PlatformImeData.WantVisible = true;
                g.PlatformImeData.InputPos = ImVec2(cursor_screen_pos.x - 1.0f, cursor_screen_pos.y - g.FontSize);
                g.PlatformImeData.InputLineHeight = g.FontSize;
            }
        }
    }
    else
    {
        // Render text only (no selection, no cursor)
        if (is_multiline)
            text_size = ImVec2(inner_size.x, InputTextCalcTextLenAndLineCount(buf_display, &buf_display_end) * g.FontSize); // We don't need width
        else if (!is_displaying_hint && g.ActiveId == id)
            buf_display_end = buf_display + state->CurLenA;
        else if (!is_displaying_hint)
            buf_display_end = buf_display + strlen(buf_display);

        if (is_multiline || (buf_display_end - buf_display) < buf_display_max_length)
        {
            ImU32 col = GetColorU32(is_displaying_hint ? c::text::text : c::text::text_active);
            draw_window->DrawList->AddText(g.Font, g.FontSize, draw_pos, col, buf_display, buf_display_end, 0.0f, is_multiline ? NULL : &clip_rect);
        }
    }

    if (is_password && !is_displaying_hint)
        PopFont();

    if (is_multiline)
    {
        // For focus requests to work on our multiline we need to ensure our child ItemAdd() call specifies the SegaUiItemFlags_Inputable (ref issue #4761)...
        Dummy(ImVec2(text_size.x, text_size.y + style.FramePadding.y));
        SegaUiItemFlags backup_item_flags = g.CurrentItemFlags;
        g.CurrentItemFlags |= SegaUiItemFlags_Inputable | SegaUiItemFlags_NoTabStop;
        EndChild();
        item_data_backup.StatusFlags |= (g.LastItemData.StatusFlags & SegaUiItemStatusFlags_HoveredWindow);
        g.CurrentItemFlags = backup_item_flags;

        // ...and then we need to undo the group overriding last item data, which gets a bit messy as EndGroup() tries to forward scrollbar being active...
        // FIXME: This quite messy/tricky, should attempt to get rid of the child window.
        EndGroup();
        if (g.LastItemData.ID == 0)
        {
            g.LastItemData.ID = id;
            g.LastItemData.InFlags = item_data_backup.InFlags;
            g.LastItemData.StatusFlags = item_data_backup.StatusFlags;
        }
    }

    // Log as text
    if (g.LogEnabled && (!is_password || is_displaying_hint))
    {
        LogSetNextTextDecoration("{", "}");
        LogRenderedText(&draw_pos, buf_display, buf_display_end);
    }

    if (value_changed && !(flags & SegaUiInputTextFlags_NoMarkEdited)) MarkItemEdited(id);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags | SegaUiItemStatusFlags_Inputable);
    if ((flags & SegaUiInputTextFlags_EnterReturnsTrue) != 0)
        return validated;
    else
        return value_changed;
}

void SegaUi::DebugNodeInputTextState(SegaUiInputTextState* state)
{
#ifndef SEGAUI_DISABLE_DEBUG_TOOLS
    SegaUiContext& g = *GSegaUi;
    ImStb::STB_TexteditState* stb_state = &state->Stb;
    ImStb::StbUndoState* undo_state = &stb_state->undostate;
    Text("ID: 0x%08X, ActiveID: 0x%08X", state->ID, g.ActiveId);
    DebugLocateItemOnHover(state->ID);
    Text("CurLenW: %d, CurLenA: %d, Cursor: %d, Selection: %d..%d", state->CurLenW, state->CurLenA, stb_state->cursor, stb_state->select_start, stb_state->select_end);
    Text("has_preferred_x: %d (%.2f)", stb_state->has_preferred_x, stb_state->preferred_x);
    Text("undo_point: %d, redo_point: %d, undo_char_point: %d, redo_char_point: %d", undo_state->undo_point, undo_state->redo_point, undo_state->undo_char_point, undo_state->redo_char_point);
    if (BeginChild("undopoints", ImVec2(0.0f, GetTextLineHeight() * 15), true)) // Visualize undo state
    {
        PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(0, 0));
        for (int n = 0; n < STB_TEXTEDIT_UNDOSTATECOUNT; n++)
        {
            ImStb::StbUndoRecord* undo_rec = &undo_state->undo_rec[n];
            const char undo_rec_type = (n < undo_state->undo_point) ? 'u' : (n >= undo_state->redo_point) ? 'r' : ' ';
            if (undo_rec_type == ' ')
                BeginDisabled();
            char buf[64] = "";
            if (undo_rec_type != ' ' && undo_rec->char_storage != -1)
                ImTextStrToUtf8(buf, IM_ARRAYSIZE(buf), undo_state->undo_char + undo_rec->char_storage, undo_state->undo_char + undo_rec->char_storage + undo_rec->insert_length);
            Text("%c [%02d] where %03d, insert %03d, delete %03d, char_storage %03d \"%s\"",
                undo_rec_type, n, undo_rec->where, undo_rec->insert_length, undo_rec->delete_length, undo_rec->char_storage, buf);
            if (undo_rec_type == ' ')
                EndDisabled();
        }
        PopStyleVar();
    }
    EndChild();
#else
    IM_UNUSED(state);
#endif
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: ColorEdit, ColorPicker, ColorButton, etc.
//-------------------------------------------------------------------------
// - ColorEdit3()
// - ColorEdit4()
// - ColorPicker3()
// - RenderColorRectWithAlphaCheckerboard() [Internal]
// - ColorPicker4()
// - ColorButton()
// - SetColorEditOptions()
// - ColorTooltip() [Internal]
// - ColorEditOptionsPopup() [Internal]
// - ColorPickerOptionsPopup() [Internal]
//-------------------------------------------------------------------------

bool SegaUi::ColorEdit3(const char* label, float col[3], SegaUiColorEditFlags flags)
{
    return ColorEdit4(label, col, flags | SegaUiColorEditFlags_NoAlpha);
}

static void ColorEditRestoreH(const float* col, float* H)
{
    SegaUiContext& g = *GSegaUi;
    IM_ASSERT(g.ColorEditCurrentID != 0);
    if (g.ColorEditSavedID != g.ColorEditCurrentID || g.ColorEditSavedColor != SegaUi::ColorConvertFloat4ToU32(ImVec4(col[0], col[1], col[2], 0)))
        return;
    *H = g.ColorEditSavedHue;
}

// ColorEdit supports RGB and HSV inputs. In case of RGB input resulting color may have undefined hue and/or saturation.
// Since widget displays both RGB and HSV values we must preserve hue and saturation to prevent these values resetting.
static void ColorEditRestoreHS(const float* col, float* H, float* S, float* V)
{
    SegaUiContext& g = *GSegaUi;
    IM_ASSERT(g.ColorEditCurrentID != 0);
    if (g.ColorEditSavedID != g.ColorEditCurrentID || g.ColorEditSavedColor != SegaUi::ColorConvertFloat4ToU32(ImVec4(col[0], col[1], col[2], 0)))
        return;

    // When S == 0, H is undefined.
    // When H == 1 it wraps around to 0.
    if (*S == 0.0f || (*H == 0.0f && g.ColorEditSavedHue == 1))
        *H = g.ColorEditSavedHue;

    // When V == 0, S is undefined.
    if (*V == 0.0f)
        *S = g.ColorEditSavedSat;
}

bool SegaUi::ColorEdit4(const char* label, float col[4], SegaUiColorEditFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const float square_sz = GetFrameHeight();
    const float w_full = CalcItemWidth();
    const float w_button = (flags & SegaUiColorEditFlags_NoSmallPreview) ? 0.0f : (square_sz + style.ItemInnerSpacing.x);
    const float w_inputs = w_full - w_button;
    const char* label_display_end = FindRenderedTextEnd(label);

    g.NextItemData.ClearFlags();

    BeginGroup();
    PushID(label);
    const bool set_current_color_edit_id = (g.ColorEditCurrentID == 0);
    if (set_current_color_edit_id)
        g.ColorEditCurrentID = window->IDStack.back();

    // If we're not showing any slider there's no point in doing any HSV conversions
    const SegaUiColorEditFlags flags_untouched = flags;
    if (flags & SegaUiColorEditFlags_NoInputs)
        flags = (flags & (~SegaUiColorEditFlags_DisplayMask_)) | SegaUiColorEditFlags_DisplayRGB | SegaUiColorEditFlags_NoOptions;

    // Context menu: display and modify options (before defaults are applied)
    if (!(flags & SegaUiColorEditFlags_NoOptions))
        ColorEditOptionsPopup(col, flags);

    // Read stored options
    if (!(flags & SegaUiColorEditFlags_DisplayMask_))
        flags |= (g.ColorEditOptions & SegaUiColorEditFlags_DisplayMask_);
    if (!(flags & SegaUiColorEditFlags_DataTypeMask_))
        flags |= (g.ColorEditOptions & SegaUiColorEditFlags_DataTypeMask_);
    if (!(flags & SegaUiColorEditFlags_PickerMask_))
        flags |= (g.ColorEditOptions & SegaUiColorEditFlags_PickerMask_);
    if (!(flags & SegaUiColorEditFlags_InputMask_))
        flags |= (g.ColorEditOptions & SegaUiColorEditFlags_InputMask_);
    flags |= (g.ColorEditOptions & ~(SegaUiColorEditFlags_DisplayMask_ | SegaUiColorEditFlags_DataTypeMask_ | SegaUiColorEditFlags_PickerMask_ | SegaUiColorEditFlags_InputMask_));
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_DisplayMask_)); // Check that only 1 is selected
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_InputMask_));   // Check that only 1 is selected

    const bool alpha = (flags & SegaUiColorEditFlags_NoAlpha) == 0;
    const bool hdr = (flags & SegaUiColorEditFlags_HDR) != 0;
    const int components = alpha ? 4 : 3;

    // Convert to the formats we need
    float f[4] = { col[0], col[1], col[2], alpha ? col[3] : 1.0f };
    if ((flags & SegaUiColorEditFlags_InputHSV) && (flags & SegaUiColorEditFlags_DisplayRGB))
        ColorConvertHSVtoRGB(f[0], f[1], f[2], f[0], f[1], f[2]);
    else if ((flags & SegaUiColorEditFlags_InputRGB) && (flags & SegaUiColorEditFlags_DisplayHSV))
    {
        // Hue is lost when converting from grayscale rgb (saturation=0). Restore it.
        ColorConvertRGBtoHSV(f[0], f[1], f[2], f[0], f[1], f[2]);
        ColorEditRestoreHS(col, &f[0], &f[1], &f[2]);
    }
    int i[4] = { IM_F32_TO_INT8_UNBOUND(f[0]), IM_F32_TO_INT8_UNBOUND(f[1]), IM_F32_TO_INT8_UNBOUND(f[2]), IM_F32_TO_INT8_UNBOUND(f[3]) };

    bool value_changed = false;
    bool value_changed_as_float = false;

    const ImVec2 pos = window->DC.CursorPos;
    const float inputs_offset_x = (style.ColorButtonPosition == SegaUiDir_Left) ? w_button : 0.0f;
    window->DC.CursorPos.x = pos.x + inputs_offset_x;

    if ((flags & (SegaUiColorEditFlags_DisplayRGB | SegaUiColorEditFlags_DisplayHSV)) != 0 && (flags & SegaUiColorEditFlags_NoInputs) == 0)
    {
        // RGB/HSV 0..255 Sliders
        const float w_item_one = ImMax(1.0f, IM_FLOOR((w_inputs - (style.ItemInnerSpacing.x) * (components - 1)) / (float)components));
        const float w_item_last = ImMax(1.0f, IM_FLOOR(w_inputs - (w_item_one + style.ItemInnerSpacing.x) * (components - 1)));

        const bool hide_prefix = (w_item_one <= CalcTextSize((flags & SegaUiColorEditFlags_Float) ? "M:0.000" : "M:000").x);
        static const char* ids[4] = { "##X", "##Y", "##Z", "##W" };
        static const char* fmt_table_int[3][4] =
        {
            {   "%3d",   "%3d",   "%3d",   "%3d" }, // Short display
            { "R:%3d", "G:%3d", "B:%3d", "A:%3d" }, // Long display for RGBA
            { "H:%3d", "S:%3d", "V:%3d", "A:%3d" }  // Long display for HSVA
        };
        static const char* fmt_table_float[3][4] =
        {
            {   "%0.3f",   "%0.3f",   "%0.3f",   "%0.3f" }, // Short display
            { "R:%0.3f", "G:%0.3f", "B:%0.3f", "A:%0.3f" }, // Long display for RGBA
            { "H:%0.3f", "S:%0.3f", "V:%0.3f", "A:%0.3f" }  // Long display for HSVA
        };
        const int fmt_idx = hide_prefix ? 0 : (flags & SegaUiColorEditFlags_DisplayHSV) ? 2 : 1;

        for (int n = 0; n < components; n++)
        {
            if (n > 0)
                SameLine(0, style.ItemInnerSpacing.x);
            SetNextItemWidth((n + 1 < components) ? w_item_one : w_item_last);

            // FIXME: When SegaUiColorEditFlags_HDR flag is passed HS values snap in weird ways when SV values go below 0.
            if (flags & SegaUiColorEditFlags_Float)
            {
                value_changed |= DragFloat(ids[n], &f[n], 1.0f / 255.0f, 0.0f, hdr ? 0.0f : 1.0f, fmt_table_float[fmt_idx][n]);
                value_changed_as_float |= value_changed;
            }
            else
            {
                value_changed |= DragInt(ids[n], &i[n], 1.0f, 0, hdr ? 0 : 255, fmt_table_int[fmt_idx][n]);
            }
            if (!(flags & SegaUiColorEditFlags_NoOptions))
                OpenPopupOnItemClick("context", SegaUiPopupFlags_MouseButtonRight);
        }
    }
    else if ((flags & SegaUiColorEditFlags_DisplayHex) != 0 && (flags & SegaUiColorEditFlags_NoInputs) == 0)
    {
        // RGB Hexadecimal Input
        char buf[64];
        if (alpha)
            ImFormatString(buf, IM_ARRAYSIZE(buf), "#%02X%02X%02X%02X", ImClamp(i[0], 0, 255), ImClamp(i[1], 0, 255), ImClamp(i[2], 0, 255), ImClamp(i[3], 0, 255));
        else
            ImFormatString(buf, IM_ARRAYSIZE(buf), "#%02X%02X%02X", ImClamp(i[0], 0, 255), ImClamp(i[1], 0, 255), ImClamp(i[2], 0, 255));
        SetNextItemWidth(w_inputs);
        if (InputText("##Text", buf, IM_ARRAYSIZE(buf), SegaUiInputTextFlags_CharsHexadecimal | SegaUiInputTextFlags_CharsUppercase))
        {
            value_changed = true;
            char* p = buf;
            while (*p == '#' || ImCharIsBlankA(*p))
                p++;
            i[0] = i[1] = i[2] = 0;
            i[3] = 0xFF; // alpha default to 255 is not parsed by scanf (e.g. inputting #FFFFFF omitting alpha)
            int r;
            if (alpha)
                r = sscanf(p, "%02X%02X%02X%02X", (unsigned int*)&i[0], (unsigned int*)&i[1], (unsigned int*)&i[2], (unsigned int*)&i[3]); // Treat at unsigned (%X is unsigned)
            else
                r = sscanf(p, "%02X%02X%02X", (unsigned int*)&i[0], (unsigned int*)&i[1], (unsigned int*)&i[2]);
            IM_UNUSED(r); // Fixes C6031: Return value ignored: 'sscanf'.
        }
        if (!(flags & SegaUiColorEditFlags_NoOptions))
            OpenPopupOnItemClick("context", SegaUiPopupFlags_MouseButtonRight);
    }

    SegaUiWindow* picker_active_window = NULL;
    if (!(flags & SegaUiColorEditFlags_NoSmallPreview))
    {
        const float button_offset_x = ((flags & SegaUiColorEditFlags_NoInputs) || (style.ColorButtonPosition == SegaUiDir_Left)) ? 0.0f : w_inputs + style.ItemInnerSpacing.x;
        window->DC.CursorPos = ImVec2(pos.x + button_offset_x, pos.y);

        const ImVec4 col_v4(col[0], col[1], col[2], alpha ? col[3] : 1.0f);
        if (ColorButton("##ColorButton", col_v4, flags))
        {
            if (!(flags & SegaUiColorEditFlags_NoPicker))
            {
                // Store current color and open a picker
                g.ColorPickerRef = col_v4;
                OpenPopup("picker");
                SetNextWindowPos(g.LastItemData.Rect.GetBL() + ImVec2(0.0f, style.ItemSpacing.y));
            }
        }
        if (!(flags & SegaUiColorEditFlags_NoOptions))
            OpenPopupOnItemClick("context", SegaUiPopupFlags_MouseButtonRight);

        PushStyleColor(SegaUiCol_PopupBg, GetColorU32(c::child::background));
        PushStyleColor(SegaUiCol_Border, GetColorU32(c::picker::outline));

        PushStyleVar(SegaUiStyleVar_PopupRounding, c::picker::rounding);
        PushStyleVar(SegaUiStyleVar_WindowPadding, ImVec2(5, 5));

        if (BeginPopup("picker"))
        {
            if (g.CurrentWindow->BeginCount == 1)
            {
                picker_active_window = g.CurrentWindow;

                SegaUiColorEditFlags picker_flags_to_forward = SegaUiColorEditFlags_DataTypeMask_ | SegaUiColorEditFlags_PickerMask_ | SegaUiColorEditFlags_InputMask_ | SegaUiColorEditFlags_HDR | SegaUiColorEditFlags_NoAlpha | SegaUiColorEditFlags_AlphaBar;
                SegaUiColorEditFlags picker_flags = (flags_untouched & picker_flags_to_forward) | SegaUiColorEditFlags_DisplayMask_ | SegaUiColorEditFlags_NoLabel | SegaUiColorEditFlags_AlphaPreviewHalf;
                SetNextItemWidth(square_sz * 12.0f); // Use 256 + bar sizes?
                value_changed |= ColorPicker4("##picker", col, picker_flags, &g.ColorPickerRef.x);
            }
            EndPopup();
        }
        PopStyleColor(2);
        PopStyleVar(2);
    }

    if (label != label_display_end && !(flags & SegaUiColorEditFlags_NoLabel))
    {
        char buf[64];

        SameLine(0.0f, style.ItemInnerSpacing.x);
        window->DC.CursorPos.x = pos.x - w_button + ((flags & SegaUiColorEditFlags_NoInputs) ? w_button : w_full);


        SegaUi::GetWindowDrawList()->AddText(window->DC.CursorPos + ImVec2(0, 0), GetColorU32(c::text::text_active), label);

        ImFormatString(buf, IM_ARRAYSIZE(buf), "#%02X%02X%02X", ImClamp(i[0], 0, 255), ImClamp(i[1], 0, 255), ImClamp(i[2], 0, 255));

    }

    // Convert back
    if (value_changed && picker_active_window == NULL)
    {
        if (!value_changed_as_float)
            for (int n = 0; n < 4; n++)
                f[n] = i[n] / 255.0f;
        if ((flags & SegaUiColorEditFlags_DisplayHSV) && (flags & SegaUiColorEditFlags_InputRGB))
        {
            g.ColorEditSavedHue = f[0];
            g.ColorEditSavedSat = f[1];
            ColorConvertHSVtoRGB(f[0], f[1], f[2], f[0], f[1], f[2]);
            g.ColorEditSavedID = g.ColorEditCurrentID;
            g.ColorEditSavedColor = ColorConvertFloat4ToU32(ImVec4(f[0], f[1], f[2], 0));
        }
        if ((flags & SegaUiColorEditFlags_DisplayRGB) && (flags & SegaUiColorEditFlags_InputHSV))
            ColorConvertRGBtoHSV(f[0], f[1], f[2], f[0], f[1], f[2]);

        col[0] = f[0];
        col[1] = f[1];
        col[2] = f[2];
        if (alpha)
            col[3] = f[3];
    }

    if (set_current_color_edit_id)
        g.ColorEditCurrentID = 0;
    PopID();
    EndGroup();

    // Drag and Drop Target
    // NB: The flag test is merely an optional micro-optimization, BeginDragDropTarget() does the same test.
    if ((g.LastItemData.StatusFlags & SegaUiItemStatusFlags_HoveredRect) && !(flags & SegaUiColorEditFlags_NoDragDrop) && BeginDragDropTarget())
    {
        bool accepted_drag_drop = false;
        if (const SegaUiPayload* payload = AcceptDragDropPayload(SEGAUI_PAYLOAD_TYPE_COLOR_3F))
        {
            memcpy((float*)col, payload->Data, sizeof(float) * 3); // Preserve alpha if any //-V512 //-V1086
            value_changed = accepted_drag_drop = true;
        }
        if (const SegaUiPayload* payload = AcceptDragDropPayload(SEGAUI_PAYLOAD_TYPE_COLOR_4F))
        {
            memcpy((float*)col, payload->Data, sizeof(float) * components);
            value_changed = accepted_drag_drop = true;
        }

        // Drag-drop payloads are always RGB
        if (accepted_drag_drop && (flags & SegaUiColorEditFlags_InputHSV))
            ColorConvertRGBtoHSV(col[0], col[1], col[2], col[0], col[1], col[2]);
        EndDragDropTarget();
    }

    // When picker is being actively used, use its active id so IsItemActive() will function on ColorEdit4().
    if (picker_active_window && g.ActiveId != 0 && g.ActiveIdWindow == picker_active_window)
        g.LastItemData.ID = g.ActiveId;

    if (value_changed && g.LastItemData.ID != 0) // In case of ID collision, the second EndGroup() won't catch g.ActiveId
        MarkItemEdited(g.LastItemData.ID);

    return value_changed;
}

bool SegaUi::ColorPicker3(const char* label, float col[3], SegaUiColorEditFlags flags)
{
    float col4[4] = { col[0], col[1], col[2], 1.0f };
    if (!ColorPicker4(label, col4, flags | SegaUiColorEditFlags_NoAlpha))
        return false;
    col[0] = col4[0]; col[1] = col4[1]; col[2] = col4[2];
    return true;
}

// Helper for ColorPicker4()
static void RenderArrowsForVerticalBar(ImDrawList* draw_list, ImVec2 pos, ImVec2 half_sz, float bar_w, float alpha)
{
    ImU32 alpha8 = IM_F32_TO_INT8_SAT(alpha);
    SegaUi::RenderArrowPointingAt(draw_list, ImVec2(pos.x + half_sz.x + 1, pos.y), ImVec2(half_sz.x + 2, half_sz.y + 1), SegaUiDir_Right, IM_COL32(0, 0, 0, alpha8));
    SegaUi::RenderArrowPointingAt(draw_list, ImVec2(pos.x + half_sz.x, pos.y), half_sz, SegaUiDir_Right, IM_COL32(255, 255, 255, alpha8));
    SegaUi::RenderArrowPointingAt(draw_list, ImVec2(pos.x + bar_w - half_sz.x - 1, pos.y), ImVec2(half_sz.x + 2, half_sz.y + 1), SegaUiDir_Left, IM_COL32(0, 0, 0, alpha8));
    SegaUi::RenderArrowPointingAt(draw_list, ImVec2(pos.x + bar_w - half_sz.x, pos.y), half_sz, SegaUiDir_Left, IM_COL32(255, 255, 255, alpha8));
}

// Note: ColorPicker4() only accesses 3 floats if SegaUiColorEditFlags_NoAlpha flag is set.
// (In C++ the 'float col[4]' notation for a function argument is equivalent to 'float* col', we only specify a size to facilitate understanding of the code.)
// FIXME: we adjust the big color square height based on item width, which may cause a flickering feedback loop (if automatic height makes a vertical scrollbar appears, affecting automatic width..)
// FIXME: this is trying to be aware of style.Alpha but not fully correct. Also, the color wheel will have overlapping glitches with (style.Alpha < 1.0)
struct picker_state
{
    float hue_bar;
    float alpha_bar;
    float circle;
    ImVec2 circle_move;
};

bool SegaUi::ColorPicker4(const char* label, float col[4], SegaUiColorEditFlags flags, const float* ref_col)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    ImDrawList* draw_list = window->DrawList;
    SegaUiStyle& style = g.Style;
    SegaUiIO& io = g.IO;

    const float width = CalcItemWidth();
    g.NextItemData.ClearFlags();

    PushID(label);
    BeginGroup();

    if (!(flags & SegaUiColorEditFlags_NoSidePreview))
        flags |= SegaUiColorEditFlags_NoSmallPreview;

    if (!(flags & SegaUiColorEditFlags_NoOptions))
        ColorPickerOptionsPopup(col, flags);

    // Read stored options
    if (!(flags & SegaUiColorEditFlags_PickerMask_))
        flags |= ((g.ColorEditOptions & SegaUiColorEditFlags_PickerMask_) ? g.ColorEditOptions : SegaUiColorEditFlags_DefaultOptions_) & SegaUiColorEditFlags_PickerMask_;
    if (!(flags & SegaUiColorEditFlags_InputMask_))
        flags |= ((g.ColorEditOptions & SegaUiColorEditFlags_InputMask_) ? g.ColorEditOptions : SegaUiColorEditFlags_DefaultOptions_) & SegaUiColorEditFlags_InputMask_;
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_PickerMask_)); // Check that only 1 is selected
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_InputMask_));  // Check that only 1 is selected
    if (!(flags & SegaUiColorEditFlags_NoOptions))
        flags |= (g.ColorEditOptions & SegaUiColorEditFlags_AlphaBar);

    // Setup
    int components = (flags & SegaUiColorEditFlags_NoAlpha) ? 3 : 4;
    bool alpha_bar = (flags & SegaUiColorEditFlags_AlphaBar) && !(flags & SegaUiColorEditFlags_NoAlpha);
    ImVec2 picker_pos = window->DC.CursorPos;
    ImVec2 bar_pos = window->DC.CursorPos + ImVec2(0, 133);
    float square_sz = GetFrameHeight();
    float bars_width = 209.f; // Arbitrary smallish width of Hue/Alpha picking bars
    float sv_picker_size = ImMax(bars_width * 1, width - (alpha_bar ? 2 : 1) * (bars_width + style.ItemInnerSpacing.x)) + 0; // Saturation/Value picking box
    float sv_bar_size = 23; // Saturation/Value picking box
    float bar0_pos_x = GetWindowPos().x + style.WindowPadding.x;
    float bar1_pos_x = bar0_pos_x;
    float bars_triangles_half_sz = IM_FLOOR(bars_width * 0.20f);

    float backup_initial_col[4];
    memcpy(backup_initial_col, col, components * sizeof(float));

    float wheel_thickness = sv_picker_size * 0.08f;
    float wheel_r_outer = sv_picker_size * 0.50f;
    float wheel_r_inner = wheel_r_outer - wheel_thickness;
    ImVec2 wheel_center(picker_pos.x + (sv_picker_size + bars_width) * 0.5f, picker_pos.y + sv_picker_size * 0.5f);

    // Note: the triangle is displayed rotated with triangle_pa pointing to Hue, but most coordinates stays unrotated for logic.
    float triangle_r = wheel_r_inner - (int)(sv_picker_size * 0.027f);
    ImVec2 triangle_pa = ImVec2(triangle_r, 0.0f); // Hue point.
    ImVec2 triangle_pb = ImVec2(triangle_r * -0.5f, triangle_r * -0.866025f); // Black point.
    ImVec2 triangle_pc = ImVec2(triangle_r * -0.5f, triangle_r * +0.866025f); // White point.

    float H = col[0], S = col[1], V = col[2];
    float R = col[0], G = col[1], B = col[2];
    if (flags & SegaUiColorEditFlags_InputRGB)
    {
        // Hue is lost when converting from greyscale rgb (saturation=0). Restore it.
        ColorConvertRGBtoHSV(R, G, B, H, S, V);
        ColorEditRestoreHS(col, &H, &S, &V);
    }
    else if (flags & SegaUiColorEditFlags_InputHSV)
    {
        ColorConvertHSVtoRGB(H, S, V, R, G, B);
    }

    bool value_changed = false, value_changed_h = false, value_changed_sv = false;

    PushItemFlag(SegaUiItemFlags_NoNav, true);

    // SV rectangle logic
    InvisibleButton("sv", ImVec2(sv_picker_size, sv_picker_size - 80));
    if (IsItemActive())
    {
        S = ImSaturate((io.MousePos.x - picker_pos.x) / (sv_picker_size - 1));
        V = 1.0f - ImSaturate((io.MousePos.y - picker_pos.y) / (sv_picker_size - 80));

        // Greatly reduces hue jitter and reset to 0 when hue == 255 and color is rapidly modified using SV square.
        if (g.ColorEditSavedColor == ColorConvertFloat4ToU32(ImVec4(col[0], col[1], col[2], 0)))
            H = g.ColorEditSavedHue;
        value_changed = value_changed_sv = true;
    }

    // Hue bar logic
    SetCursorScreenPos(ImVec2(bar0_pos_x, bar_pos.y));
    InvisibleButton("hue", ImVec2(bars_width, sv_bar_size));
    if (IsItemActive())
    {
        H = 1.f - ImSaturate((io.MousePos.x - bar_pos.x) / (bars_width - 1));
        value_changed = value_changed_h = true;
    }

    // Alpha bar logic
    if (alpha_bar)
    {
        SetCursorScreenPos(ImVec2(bar1_pos_x, bar_pos.y + 16));
        InvisibleButton("alpha", ImVec2(bars_width, sv_bar_size));
        if (IsItemActive())
        {
            col[3] = ImSaturate((io.MousePos.x - bar_pos.x) / (bars_width - 1));
            value_changed = true;
        }
    }
    PopItemFlag(); // SegaUiItemFlags_NoNav

    // Convert back color to RGB
    if (value_changed_h || value_changed_sv)
    {
        if (flags & SegaUiColorEditFlags_InputRGB)
        {
            ColorConvertHSVtoRGB(H, S, V, col[0], col[1], col[2]);
            g.ColorEditSavedHue = H;
            g.ColorEditSavedSat = S;
            g.ColorEditSavedColor = ColorConvertFloat4ToU32(ImVec4(col[0], col[1], col[2], 0));
        }
        else if (flags & SegaUiColorEditFlags_InputHSV)
        {
            col[0] = H;
            col[1] = S;
            col[2] = V;
        }
    }

    // R,G,B and H,S,V slider color editor
    bool value_changed_fix_hue_wrap = false;

    if (value_changed_fix_hue_wrap && (flags & SegaUiColorEditFlags_InputRGB))
    {
        float new_H, new_S, new_V;
        ColorConvertRGBtoHSV(col[0], col[1], col[2], new_H, new_S, new_V);
        if (new_H <= 0 && H > 0)
        {
            if (new_V <= 0 && V != new_V)
                ColorConvertHSVtoRGB(H, S, new_V <= 0 ? V * 0.5f : new_V, col[0], col[1], col[2]);
            else if (new_S <= 0)
                ColorConvertHSVtoRGB(H, new_S <= 0 ? S * 0.5f : new_S, new_V, col[0], col[1], col[2]);
        }
    }

    if (value_changed)
    {
        if (flags & SegaUiColorEditFlags_InputRGB)
        {
            R = col[0];
            G = col[1];
            B = col[2];
            ColorConvertRGBtoHSV(R, G, B, H, S, V);
            ColorEditRestoreHS(col, &H, &S, &V);   // Fix local Hue as display below will use it immediately.
        }
        else if (flags & SegaUiColorEditFlags_InputHSV)
        {
            H = col[0];
            S = col[1];
            V = col[2];
            ColorConvertHSVtoRGB(H, S, V, R, G, B);
        }
    }

    const int style_alpha8 = IM_F32_TO_INT8_SAT(style.Alpha);
    const ImU32 col_black = IM_COL32(0, 0, 0, style_alpha8);
    const ImU32 col_white = IM_COL32(255, 255, 255, style_alpha8);
    const ImU32 col_midgrey = IM_COL32(128, 128, 128, style_alpha8);
    const ImU32 col_hues[7] = { IM_COL32(255,0,0,style_alpha8), IM_COL32(255,0,255,style_alpha8), IM_COL32(0,0,255,style_alpha8),IM_COL32(0,255,255,style_alpha8), IM_COL32(0,255,0,style_alpha8), IM_COL32(255,255,0,style_alpha8), IM_COL32(255,0,0,style_alpha8) };
    //const ImU32 col_hues[7] = { IM_COL32(255,0,0,style_alpha8), IM_COL32(255,255,0,style_alpha8), IM_COL32(0,255,0,style_alpha8), IM_COL32(0,255,255,style_alpha8), IM_COL32(0,0,255,style_alpha8), IM_COL32(255,0,255,style_alpha8), IM_COL32(255,0,0,style_alpha8) };

    ImVec4 hue_color_f(1, 1, 1, style.Alpha); ColorConvertHSVtoRGB(H, 1, 1, hue_color_f.x, hue_color_f.y, hue_color_f.z);
    ImU32 hue_color32 = ColorConvertFloat4ToU32(hue_color_f);
    ImU32 user_col32_striped_of_alpha = ColorConvertFloat4ToU32(ImVec4(R, G, B, style.Alpha)); // Important: this is still including the main rendering/style alpha!!

    ImVec2 sv_cursor_pos;

    GetForegroundDrawList()->AddRectFilledMultiColorRounded(picker_pos, picker_pos + ImVec2(sv_picker_size, sv_picker_size - 80), GetColorU32(SegaUiCol_PopupBg), col_white, hue_color32, hue_color32, col_white, c::picker::rounding, ImDrawCornerFlags_All);
    GetForegroundDrawList()->AddRectFilledMultiColorRounded(picker_pos, picker_pos + ImVec2(sv_picker_size, sv_picker_size - 80), GetColorU32(SegaUiCol_PopupBg), 0, 0, col_black, col_black, c::picker::rounding, ImDrawCornerFlags_All);
    RenderFrameBorder(picker_pos, picker_pos + ImVec2(sv_picker_size, sv_picker_size), 0.0f);
    sv_cursor_pos.x = ImClamp(IM_ROUND(picker_pos.x + ImSaturate(S) * sv_picker_size), picker_pos.x, picker_pos.x + sv_picker_size - 2); // Sneakily prevent the circle to stick out too much
    sv_cursor_pos.y = ImClamp(IM_ROUND(picker_pos.y + ImSaturate(1 - V) * (sv_picker_size - 80)), picker_pos.y + 2, picker_pos.y + sv_picker_size - 80);

    static std::map<SegaUiID, picker_state> anim;
    auto it_anim = anim.find(SegaUi::GetID(label));

    if (it_anim == anim.end())
    {
        anim.insert({ SegaUi::GetID(label), picker_state() });
        it_anim = anim.find(SegaUi::GetID(label));
    }

    // Render Hue Bar
    for (int i = 0; i < 6; ++i)
        GetForegroundDrawList()->AddRectFilledMultiColor(ImVec2(bar0_pos_x + i * (bars_width / 6), bar_pos.y + 6), ImVec2(bar0_pos_x + (i + 1) * (bars_width / 6), bar_pos.y + sv_bar_size - 7), col_hues[i], col_hues[i + 1], col_hues[i + 1], col_hues[i]);
    GetForegroundDrawList()->AddRectFilledMultiColorRounded(ImVec2(bar0_pos_x, bar_pos.y + 6), ImVec2(bar0_pos_x + bars_width, bar_pos.y + sv_bar_size - 7), GetColorU32(SegaUiCol_PopupBg), 0, 0, 0, 0, 30.f, ImDrawCornerFlags_All);

    float bar0_line_x = IM_ROUND(bar_pos.x + (1.f - H) * bars_width);

    bar0_line_x = ImClamp(bar0_line_x, picker_pos.x + 3.f, picker_pos.x + 204.f);

    it_anim->second.hue_bar = ImLerp(it_anim->second.hue_bar, bar0_line_x - bar_pos.x, g.IO.DeltaTime * 20.f);

    GetForegroundDrawList()->AddRectFilled(ImVec2(it_anim->second.hue_bar + bar_pos.x - 3, bar_pos.y + 3), ImVec2(it_anim->second.hue_bar + bar_pos.x + 5, bar_pos.y + 19), ImColor(255, 255, 255, 255), 30.f);

    it_anim->second.circle_move = ImLerp(it_anim->second.circle_move, sv_cursor_pos - bar_pos, g.IO.DeltaTime * 20.f);
    it_anim->second.circle = ImLerp(it_anim->second.circle, value_changed_sv ? 4.f : 7.f, g.IO.DeltaTime * 20.f);

    GetForegroundDrawList()->AddCircleFilled(it_anim->second.circle_move + bar_pos, it_anim->second.circle, user_col32_striped_of_alpha, 32);
    GetForegroundDrawList()->AddCircle(it_anim->second.circle_move + bar_pos + ImVec2(0, 1), it_anim->second.circle, IM_COL32(50, 50, 50, 150 * g.Style.Alpha), 32);
    GetForegroundDrawList()->AddCircle(it_anim->second.circle_move + bar_pos, it_anim->second.circle, IM_COL32(230, 230, 230, 255 * g.Style.Alpha), 32);

    if (alpha_bar)
    {
        float alpha = ImSaturate(col[3]);
        ImRect bar1_bb(bar1_pos_x, bar_pos.y + 20, bar1_pos_x + bars_width, bar_pos.y + 20 + sv_bar_size);

        RenderColorRectWithAlphaCheckerboard(draw_list, bar1_bb.Min + ImVec2(0, 8), bar1_bb.Max - ImVec2(0, 5), 0, bar1_bb.GetWidth() / 50.0f, ImVec2(0.0f, 0.0f));

        GetForegroundDrawList()->AddRectFilledMultiColor(bar1_bb.Min + ImVec2(0, 8), bar1_bb.Max - ImVec2(0, 5), user_col32_striped_of_alpha & ~IM_COL32_A_MASK, user_col32_striped_of_alpha, user_col32_striped_of_alpha, user_col32_striped_of_alpha & ~IM_COL32_A_MASK);
        GetForegroundDrawList()->AddRectFilledMultiColorRounded(bar1_bb.Min + ImVec2(0, 8), bar1_bb.Max - ImVec2(0, 5), GetColorU32(SegaUiCol_PopupBg), 0, 0, 0, 0, c::picker::rounding, ImDrawCornerFlags_All);
        float bar1_line_x = IM_ROUND(bar_pos.x + alpha * bars_width);

        bar1_line_x = ImClamp(bar1_line_x, bar_pos.x, picker_pos.x + 200.f);
        it_anim->second.alpha_bar = ImLerp(it_anim->second.alpha_bar, bar1_line_x - bar_pos.x + 5.f, g.IO.DeltaTime * 25.f);
        GetForegroundDrawList()->AddCircleFilled(ImVec2(it_anim->second.alpha_bar + bar_pos.x, bar1_bb.Min.y + 13.0f), 6, IM_COL32(255, 255, 255, 255), 100.f);
    }

    EndGroup();

    if (value_changed && memcmp(backup_initial_col, col, components * sizeof(float)) == 0)
        value_changed = false;
    if (value_changed)
        MarkItemEdited(g.LastItemData.ID);

    PopID();
    return value_changed;
}

bool SegaUi::ColorButton(const char* desc_id, const ImVec4& col, SegaUiColorEditFlags flags, const ImVec2& size_arg)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiID id = window->GetID(desc_id);
    const float default_size = GetFrameHeight();
    const ImVec2 pos = window->DC.CursorPos;
    const float width = GetContentRegionMax().x - GetStyle().WindowPadding.x;
    const ImRect rect(pos, pos + ImVec2(width, 18));
    const ImRect clickable(pos + ImVec2(width - 30, 2), pos + ImVec2(width, 19));
    ItemSize(ImRect(rect.Min, rect.Max + ImVec2(0, -1)));
    if (!ItemAdd(rect, id))
        return false;

    bool hovered, held, pressed = ButtonBehavior(clickable, id, &hovered, &held);

    if (flags & SegaUiColorEditFlags_NoAlpha)
        flags &= ~(SegaUiColorEditFlags_AlphaPreview | SegaUiColorEditFlags_AlphaPreviewHalf);

    ImVec4 col_rgb = col;
    if (flags & SegaUiColorEditFlags_InputHSV)
        ColorConvertHSVtoRGB(col_rgb.x, col_rgb.y, col_rgb.z, col_rgb.x, col_rgb.y, col_rgb.z);

    GetWindowDrawList()->AddShadowRect(clickable.Min, clickable.Max + ImVec2(0, 0), GetColorU32(col_rgb), 15.f, ImVec2(0, 0), c::picker::rounding);
    RenderColorRectWithAlphaCheckerboard(window->DrawList, clickable.Min, clickable.Max + ImVec2(0, 0), GetColorU32(col_rgb), 10, ImVec2(0.f, 0.f), c::picker::rounding);


    return pressed;
}

// Initialize/override default color options
void SegaUi::SetColorEditOptions(SegaUiColorEditFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    if ((flags & SegaUiColorEditFlags_DisplayMask_) == 0)
        flags |= SegaUiColorEditFlags_DefaultOptions_ & SegaUiColorEditFlags_DisplayMask_;
    if ((flags & SegaUiColorEditFlags_DataTypeMask_) == 0)
        flags |= SegaUiColorEditFlags_DefaultOptions_ & SegaUiColorEditFlags_DataTypeMask_;
    if ((flags & SegaUiColorEditFlags_PickerMask_) == 0)
        flags |= SegaUiColorEditFlags_DefaultOptions_ & SegaUiColorEditFlags_PickerMask_;
    if ((flags & SegaUiColorEditFlags_InputMask_) == 0)
        flags |= SegaUiColorEditFlags_DefaultOptions_ & SegaUiColorEditFlags_InputMask_;
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_DisplayMask_));    // Check only 1 option is selected
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_DataTypeMask_));   // Check only 1 option is selected
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_PickerMask_));     // Check only 1 option is selected
    IM_ASSERT(ImIsPowerOfTwo(flags & SegaUiColorEditFlags_InputMask_));      // Check only 1 option is selected
    g.ColorEditOptions = flags;
}

// Note: only access 3 floats if SegaUiColorEditFlags_NoAlpha flag is set.
void SegaUi::ColorTooltip(const char* text, const float* col, SegaUiColorEditFlags flags)
{
    SegaUiContext& g = *GSegaUi;

    if (!BeginTooltipEx(SegaUiTooltipFlags_OverridePreviousTooltip, SegaUiWindowFlags_None))
        return;
    const char* text_end = text ? FindRenderedTextEnd(text, NULL) : text;
    if (text_end > text)
    {
        TextEx(text, text_end);
        Separator();
    }

    ImVec2 sz(g.FontSize * 3 + g.Style.FramePadding.y * 2, g.FontSize * 3 + g.Style.FramePadding.y * 2);
    ImVec4 cf(col[0], col[1], col[2], (flags & SegaUiColorEditFlags_NoAlpha) ? 1.0f : col[3]);
    int cr = IM_F32_TO_INT8_SAT(col[0]), cg = IM_F32_TO_INT8_SAT(col[1]), cb = IM_F32_TO_INT8_SAT(col[2]), ca = (flags & SegaUiColorEditFlags_NoAlpha) ? 255 : IM_F32_TO_INT8_SAT(col[3]);
    ColorButton("##preview", cf, (flags & (SegaUiColorEditFlags_InputMask_ | SegaUiColorEditFlags_NoAlpha | SegaUiColorEditFlags_AlphaPreview | SegaUiColorEditFlags_AlphaPreviewHalf)) | SegaUiColorEditFlags_NoTooltip, sz);
    SameLine();
    if ((flags & SegaUiColorEditFlags_InputRGB) || !(flags & SegaUiColorEditFlags_InputMask_))
    {
        if (flags & SegaUiColorEditFlags_NoAlpha)
            Text("#%02X%02X%02X\nR: %d, G: %d, B: %d\n(%.3f, %.3f, %.3f)", cr, cg, cb, cr, cg, cb, col[0], col[1], col[2]);
        else
            Text("#%02X%02X%02X%02X\nR:%d, G:%d, B:%d, A:%d\n(%.3f, %.3f, %.3f, %.3f)", cr, cg, cb, ca, cr, cg, cb, ca, col[0], col[1], col[2], col[3]);
    }
    else if (flags & SegaUiColorEditFlags_InputHSV)
    {
        if (flags & SegaUiColorEditFlags_NoAlpha)
            Text("H: %.3f, S: %.3f, V: %.3f", col[0], col[1], col[2]);
        else
            Text("H: %.3f, S: %.3f, V: %.3f, A: %.3f", col[0], col[1], col[2], col[3]);
    }
    EndTooltip();
}

void SegaUi::ColorEditOptionsPopup(const float* col, SegaUiColorEditFlags flags)
{
    bool allow_opt_inputs = !(flags & SegaUiColorEditFlags_DisplayMask_);
    bool allow_opt_datatype = !(flags & SegaUiColorEditFlags_DataTypeMask_);
    if ((!allow_opt_inputs && !allow_opt_datatype) || !BeginPopup("context"))
        return;
    SegaUiContext& g = *GSegaUi;
    SegaUiColorEditFlags opts = g.ColorEditOptions;
    if (allow_opt_inputs)
    {
        if (RadioButton("RGB", (opts & SegaUiColorEditFlags_DisplayRGB) != 0)) opts = (opts & ~SegaUiColorEditFlags_DisplayMask_) | SegaUiColorEditFlags_DisplayRGB;
        if (RadioButton("HSV", (opts & SegaUiColorEditFlags_DisplayHSV) != 0)) opts = (opts & ~SegaUiColorEditFlags_DisplayMask_) | SegaUiColorEditFlags_DisplayHSV;
        if (RadioButton("Hex", (opts & SegaUiColorEditFlags_DisplayHex) != 0)) opts = (opts & ~SegaUiColorEditFlags_DisplayMask_) | SegaUiColorEditFlags_DisplayHex;
    }
    if (allow_opt_datatype)
    {
        if (allow_opt_inputs) Separator();
        if (RadioButton("0..255",     (opts & SegaUiColorEditFlags_Uint8) != 0)) opts = (opts & ~SegaUiColorEditFlags_DataTypeMask_) | SegaUiColorEditFlags_Uint8;
        if (RadioButton("0.00..1.00", (opts & SegaUiColorEditFlags_Float) != 0)) opts = (opts & ~SegaUiColorEditFlags_DataTypeMask_) | SegaUiColorEditFlags_Float;
    }

    if (allow_opt_inputs || allow_opt_datatype)
        Separator();
    if (Button("Copy as..", ImVec2(-1, 0)))
        OpenPopup("Copy");
    if (BeginPopup("Copy"))
    {
        int cr = IM_F32_TO_INT8_SAT(col[0]), cg = IM_F32_TO_INT8_SAT(col[1]), cb = IM_F32_TO_INT8_SAT(col[2]), ca = (flags & SegaUiColorEditFlags_NoAlpha) ? 255 : IM_F32_TO_INT8_SAT(col[3]);
        char buf[64];
        ImFormatString(buf, IM_ARRAYSIZE(buf), "(%.3ff, %.3ff, %.3ff, %.3ff)", col[0], col[1], col[2], (flags & SegaUiColorEditFlags_NoAlpha) ? 1.0f : col[3]);
        if (Selectable(buf))
            SetClipboardText(buf);
        ImFormatString(buf, IM_ARRAYSIZE(buf), "(%d,%d,%d,%d)", cr, cg, cb, ca);
        if (Selectable(buf))
            SetClipboardText(buf);
        ImFormatString(buf, IM_ARRAYSIZE(buf), "#%02X%02X%02X", cr, cg, cb);
        if (Selectable(buf))
            SetClipboardText(buf);
        if (!(flags & SegaUiColorEditFlags_NoAlpha))
        {
            ImFormatString(buf, IM_ARRAYSIZE(buf), "#%02X%02X%02X%02X", cr, cg, cb, ca);
            if (Selectable(buf))
                SetClipboardText(buf);
        }
        EndPopup();
    }

    g.ColorEditOptions = opts;
    EndPopup();
}

void SegaUi::ColorPickerOptionsPopup(const float* ref_col, SegaUiColorEditFlags flags)
{
    bool allow_opt_picker = !(flags & SegaUiColorEditFlags_PickerMask_);
    bool allow_opt_alpha_bar = !(flags & SegaUiColorEditFlags_NoAlpha) && !(flags & SegaUiColorEditFlags_AlphaBar);
    if ((!allow_opt_picker && !allow_opt_alpha_bar) || !BeginPopup("context"))
        return;
    SegaUiContext& g = *GSegaUi;
    if (allow_opt_picker)
    {
        ImVec2 picker_size(g.FontSize * 8, ImMax(g.FontSize * 8 - (GetFrameHeight() + g.Style.ItemInnerSpacing.x), 1.0f)); // FIXME: Picker size copied from main picker function
        PushItemWidth(picker_size.x);
        for (int picker_type = 0; picker_type < 2; picker_type++)
        {
            // Draw small/thumbnail version of each picker type (over an invisible button for selection)
            if (picker_type > 0) Separator();
            PushID(picker_type);
            SegaUiColorEditFlags picker_flags = SegaUiColorEditFlags_NoInputs | SegaUiColorEditFlags_NoOptions | SegaUiColorEditFlags_NoLabel | SegaUiColorEditFlags_NoSidePreview | (flags & SegaUiColorEditFlags_NoAlpha);
            if (picker_type == 0) picker_flags |= SegaUiColorEditFlags_PickerHueBar;
            if (picker_type == 1) picker_flags |= SegaUiColorEditFlags_PickerHueWheel;
            ImVec2 backup_pos = GetCursorScreenPos();
            if (Selectable("##selectable", false, 0, picker_size)) // By default, Selectable() is closing popup
                g.ColorEditOptions = (g.ColorEditOptions & ~SegaUiColorEditFlags_PickerMask_) | (picker_flags & SegaUiColorEditFlags_PickerMask_);
            SetCursorScreenPos(backup_pos);
            ImVec4 previewing_ref_col;
            memcpy(&previewing_ref_col, ref_col, sizeof(float) * ((picker_flags & SegaUiColorEditFlags_NoAlpha) ? 3 : 4));
            ColorPicker4("##previewing_picker", &previewing_ref_col.x, picker_flags);
            PopID();
        }
        PopItemWidth();
    }
    if (allow_opt_alpha_bar)
    {
        if (allow_opt_picker) Separator();
        CheckboxFlags("Alpha Bar", &g.ColorEditOptions, SegaUiColorEditFlags_AlphaBar);
    }
    EndPopup();
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: TreeNode, CollapsingHeader, etc.
//-------------------------------------------------------------------------
// - TreeNode()
// - TreeNodeV()
// - TreeNodeEx()
// - TreeNodeExV()
// - TreeNodeBehavior() [Internal]
// - TreePush()
// - TreePop()
// - GetTreeNodeToLabelSpacing()
// - SetNextItemOpen()
// - CollapsingHeader()
//-------------------------------------------------------------------------

bool SegaUi::TreeNode(const char* str_id, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    bool is_open = TreeNodeExV(str_id, 0, fmt, args);
    va_end(args);
    return is_open;
}

bool SegaUi::TreeNode(const void* ptr_id, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    bool is_open = TreeNodeExV(ptr_id, 0, fmt, args);
    va_end(args);
    return is_open;
}

bool SegaUi::TreeNode(const char* label)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;
    return TreeNodeBehavior(window->GetID(label), 0, label, NULL);
}

bool SegaUi::TreeNodeV(const char* str_id, const char* fmt, va_list args)
{
    return TreeNodeExV(str_id, 0, fmt, args);
}

bool SegaUi::TreeNodeV(const void* ptr_id, const char* fmt, va_list args)
{
    return TreeNodeExV(ptr_id, 0, fmt, args);
}

bool SegaUi::TreeNodeEx(const char* label, SegaUiTreeNodeFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    return TreeNodeBehavior(window->GetID(label), flags, label, NULL);
}

bool SegaUi::TreeNodeEx(const char* str_id, SegaUiTreeNodeFlags flags, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    bool is_open = TreeNodeExV(str_id, flags, fmt, args);
    va_end(args);
    return is_open;
}

bool SegaUi::TreeNodeEx(const void* ptr_id, SegaUiTreeNodeFlags flags, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    bool is_open = TreeNodeExV(ptr_id, flags, fmt, args);
    va_end(args);
    return is_open;
}

bool SegaUi::TreeNodeExV(const char* str_id, SegaUiTreeNodeFlags flags, const char* fmt, va_list args)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const char* label, *label_end;
    ImFormatStringToTempBufferV(&label, &label_end, fmt, args);
    return TreeNodeBehavior(window->GetID(str_id), flags, label, label_end);
}

bool SegaUi::TreeNodeExV(const void* ptr_id, SegaUiTreeNodeFlags flags, const char* fmt, va_list args)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const char* label, *label_end;
    ImFormatStringToTempBufferV(&label, &label_end, fmt, args);
    return TreeNodeBehavior(window->GetID(ptr_id), flags, label, label_end);
}

void SegaUi::TreeNodeSetOpen(SegaUiID id, bool open)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiStorage* storage = g.CurrentWindow->DC.StateStorage;
    storage->SetInt(id, open ? 1 : 0);
}

bool SegaUi::TreeNodeUpdateNextOpen(SegaUiID id, SegaUiTreeNodeFlags flags)
{
    if (flags & SegaUiTreeNodeFlags_Leaf)
        return true;

    // We only write to the tree storage if the user clicks (or explicitly use the SetNextItemOpen function)
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    SegaUiStorage* storage = window->DC.StateStorage;

    bool is_open;
    if (g.NextItemData.Flags & SegaUiNextItemDataFlags_HasOpen)
    {
        if (g.NextItemData.OpenCond & SegaUiCond_Always)
        {
            is_open = g.NextItemData.OpenVal;
            TreeNodeSetOpen(id, is_open);
        }
        else
        {
            // We treat SegaUiCond_Once and SegaUiCond_FirstUseEver the same because tree node state are not saved persistently.
            const int stored_value = storage->GetInt(id, -1);
            if (stored_value == -1)
            {
                is_open = g.NextItemData.OpenVal;
                TreeNodeSetOpen(id, is_open);
            }
            else
            {
                is_open = stored_value != 0;
            }
        }
    }
    else
    {
        is_open = storage->GetInt(id, (flags & SegaUiTreeNodeFlags_DefaultOpen) ? 1 : 0) != 0;
    }

    // When logging is enabled, we automatically expand tree nodes (but *NOT* collapsing headers.. seems like sensible behavior).
    // NB- If we are above max depth we still allow manually opened nodes to be logged.
    if (g.LogEnabled && !(flags & SegaUiTreeNodeFlags_NoAutoOpenOnLog) && (window->DC.TreeDepth - g.LogDepthRef) < g.LogDepthToExpand)
        is_open = true;

    return is_open;
}

bool SegaUi::TreeNodeBehavior(SegaUiID id, SegaUiTreeNodeFlags flags, const char* label, const char* label_end)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const bool display_frame = (flags & SegaUiTreeNodeFlags_Framed) != 0;
    const ImVec2 padding = (display_frame || (flags & SegaUiTreeNodeFlags_FramePadding)) ? style.FramePadding : ImVec2(style.FramePadding.x, ImMin(window->DC.CurrLineTextBaseOffset, style.FramePadding.y));

    if (!label_end)
        label_end = FindRenderedTextEnd(label);
    const ImVec2 label_size = CalcTextSize(label, label_end, false);

    // We vertically grow up to current line height up the typical widget height.
    const float frame_height = ImMax(ImMin(window->DC.CurrLineSize.y, g.FontSize + style.FramePadding.y * 2), label_size.y + padding.y * 2);
    ImRect frame_bb;
    frame_bb.Min.x = (flags & SegaUiTreeNodeFlags_SpanFullWidth) ? window->WorkRect.Min.x : window->DC.CursorPos.x;
    frame_bb.Min.y = window->DC.CursorPos.y;
    frame_bb.Max.x = window->WorkRect.Max.x;
    frame_bb.Max.y = window->DC.CursorPos.y + frame_height;
    if (display_frame)
    {
        // Framed header expand a little outside the default padding, to the edge of InnerClipRect
        // (FIXME: May remove this at some point and make InnerClipRect align with WindowPadding.x instead of WindowPadding.x*0.5f)
        frame_bb.Min.x -= IM_FLOOR(window->WindowPadding.x * 0.5f - 1.0f);
        frame_bb.Max.x += IM_FLOOR(window->WindowPadding.x * 0.5f);
    }

    const float text_offset_x = g.FontSize + (display_frame ? padding.x * 3 : padding.x * 2);           // Collapser arrow width + Spacing
    const float text_offset_y = ImMax(padding.y, window->DC.CurrLineTextBaseOffset);                    // Latch before ItemSize changes it
    const float text_width = g.FontSize + (label_size.x > 0.0f ? label_size.x + padding.x * 2 : 0.0f);  // Include collapser
    ImVec2 text_pos(window->DC.CursorPos.x + text_offset_x, window->DC.CursorPos.y + text_offset_y);
    ItemSize(ImVec2(text_width, frame_height), padding.y);

    // For regular tree nodes, we arbitrary allow to click past 2 worth of ItemSpacing
    ImRect interact_bb = frame_bb;
    if (!display_frame && (flags & (SegaUiTreeNodeFlags_SpanAvailWidth | SegaUiTreeNodeFlags_SpanFullWidth)) == 0)
        interact_bb.Max.x = frame_bb.Min.x + text_width + style.ItemSpacing.x * 2.0f;

    // Store a flag for the current depth to tell if we will allow closing this node when navigating one of its child.
    // For this purpose we essentially compare if g.NavIdIsAlive went from 0 to 1 between TreeNode() and TreePop().
    // This is currently only support 32 level deep and we are fine with (1 << Depth) overflowing into a zero.
    const bool is_leaf = (flags & SegaUiTreeNodeFlags_Leaf) != 0;
    bool is_open = TreeNodeUpdateNextOpen(id, flags);
    if (is_open && !g.NavIdIsAlive && (flags & SegaUiTreeNodeFlags_NavLeftJumpsBackHere) && !(flags & SegaUiTreeNodeFlags_NoTreePushOnOpen))
        window->DC.TreeJumpToParentOnPopMask |= (1 << window->DC.TreeDepth);

    bool item_add = ItemAdd(interact_bb, id);
    g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_HasDisplayRect;
    g.LastItemData.DisplayRect = frame_bb;

    if (!item_add)
    {
        if (is_open && !(flags & SegaUiTreeNodeFlags_NoTreePushOnOpen))
            TreePushOverrideID(id);
        SEGAUI_TEST_ENGINE_ITEM_INFO(g.LastItemData.ID, label, g.LastItemData.StatusFlags | (is_leaf ? 0 : SegaUiItemStatusFlags_Openable) | (is_open ? SegaUiItemStatusFlags_Opened : 0));
        return is_open;
    }

    SegaUiButtonFlags button_flags = SegaUiTreeNodeFlags_None;
    if (flags & SegaUiTreeNodeFlags_AllowItemOverlap)
        button_flags |= SegaUiButtonFlags_AllowItemOverlap;
    if (!is_leaf)
        button_flags |= SegaUiButtonFlags_PressedOnDragDropHold;

    // We allow clicking on the arrow section with keyboard modifiers held, in order to easily
    // allow browsing a tree while preserving selection with code implementing multi-selection patterns.
    // When clicking on the rest of the tree node we always disallow keyboard modifiers.
    const float arrow_hit_x1 = (text_pos.x - text_offset_x) - style.TouchExtraPadding.x;
    const float arrow_hit_x2 = (text_pos.x - text_offset_x) + (g.FontSize + padding.x * 2.0f) + style.TouchExtraPadding.x;
    const bool is_mouse_x_over_arrow = (g.IO.MousePos.x >= arrow_hit_x1 && g.IO.MousePos.x < arrow_hit_x2);
    if (window != g.HoveredWindow || !is_mouse_x_over_arrow)
        button_flags |= SegaUiButtonFlags_NoKeyModifiers;

    // Open behaviors can be altered with the _OpenOnArrow and _OnOnDoubleClick flags.
    // Some alteration have subtle effects (e.g. toggle on MouseUp vs MouseDown events) due to requirements for multi-selection and drag and drop support.
    // - Single-click on label = Toggle on MouseUp (default, when _OpenOnArrow=0)
    // - Single-click on arrow = Toggle on MouseDown (when _OpenOnArrow=0)
    // - Single-click on arrow = Toggle on MouseDown (when _OpenOnArrow=1)
    // - Double-click on label = Toggle on MouseDoubleClick (when _OpenOnDoubleClick=1)
    // - Double-click on arrow = Toggle on MouseDoubleClick (when _OpenOnDoubleClick=1 and _OpenOnArrow=0)
    // It is rather standard that arrow click react on Down rather than Up.
    // We set SegaUiButtonFlags_PressedOnClickRelease on OpenOnDoubleClick because we want the item to be active on the initial MouseDown in order for drag and drop to work.
    if (is_mouse_x_over_arrow)
        button_flags |= SegaUiButtonFlags_PressedOnClick;
    else if (flags & SegaUiTreeNodeFlags_OpenOnDoubleClick)
        button_flags |= SegaUiButtonFlags_PressedOnClickRelease | SegaUiButtonFlags_PressedOnDoubleClick;
    else
        button_flags |= SegaUiButtonFlags_PressedOnClickRelease;

    bool selected = (flags & SegaUiTreeNodeFlags_Selected) != 0;
    const bool was_selected = selected;

    bool hovered, held;
    bool pressed = ButtonBehavior(interact_bb, id, &hovered, &held, button_flags);
    bool toggled = false;
    if (!is_leaf)
    {
        if (pressed && g.DragDropHoldJustPressedId != id)
        {
            if ((flags & (SegaUiTreeNodeFlags_OpenOnArrow | SegaUiTreeNodeFlags_OpenOnDoubleClick)) == 0 || (g.NavActivateId == id))
                toggled = true;
            if (flags & SegaUiTreeNodeFlags_OpenOnArrow)
                toggled |= is_mouse_x_over_arrow && !g.NavDisableMouseHover; // Lightweight equivalent of IsMouseHoveringRect() since ButtonBehavior() already did the job
            if ((flags & SegaUiTreeNodeFlags_OpenOnDoubleClick) && g.IO.MouseClickedCount[0] == 2)
                toggled = true;
        }
        else if (pressed && g.DragDropHoldJustPressedId == id)
        {
            IM_ASSERT(button_flags & SegaUiButtonFlags_PressedOnDragDropHold);
            if (!is_open) // When using Drag and Drop "hold to open" we keep the node highlighted after opening, but never close it again.
                toggled = true;
        }

        if (g.NavId == id && g.NavMoveDir == SegaUiDir_Left && is_open)
        {
            toggled = true;
            NavClearPreferredPosForAxis(SegaUiAxis_X);
            NavMoveRequestCancel();
        }
        if (g.NavId == id && g.NavMoveDir == SegaUiDir_Right && !is_open) // If there's something upcoming on the line we may want to give it the priority?
        {
            toggled = true;
            NavClearPreferredPosForAxis(SegaUiAxis_X);
            NavMoveRequestCancel();
        }

        if (toggled)
        {
            is_open = !is_open;
            window->DC.StateStorage->SetInt(id, is_open);
            g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_ToggledOpen;
        }
    }
    if (flags & SegaUiTreeNodeFlags_AllowItemOverlap)
        SetItemAllowOverlap();

    // In this branch, TreeNodeBehavior() cannot toggle the selection so this will never trigger.
    if (selected != was_selected) //-V547
        g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_ToggledSelection;

    // Render
    const ImU32 text_col = GetColorU32(SegaUiCol_Text);
    SegaUiNavHighlightFlags nav_highlight_flags = SegaUiNavHighlightFlags_TypeThin;
    if (display_frame)
    {
        // Framed type
        const ImU32 bg_col = GetColorU32((held && hovered) ? SegaUiCol_HeaderActive : hovered ? SegaUiCol_HeaderHovered : SegaUiCol_Header);
        RenderFrame(frame_bb.Min, frame_bb.Max, bg_col, true, style.FrameRounding);
        RenderNavHighlight(frame_bb, id, nav_highlight_flags);
        if (flags & SegaUiTreeNodeFlags_Bullet)
            RenderBullet(window->DrawList, ImVec2(text_pos.x - text_offset_x * 0.60f, text_pos.y + g.FontSize * 0.5f), text_col);
        else if (!is_leaf)
            RenderArrow(window->DrawList, ImVec2(text_pos.x - text_offset_x + padding.x, text_pos.y), text_col, is_open ? SegaUiDir_Down : SegaUiDir_Right, 1.0f);
        else // Leaf without bullet, left-adjusted text
            text_pos.x -= text_offset_x;
        if (flags & SegaUiTreeNodeFlags_ClipLabelForTrailingButton)
            frame_bb.Max.x -= g.FontSize + style.FramePadding.x;

        if (g.LogEnabled)
            LogSetNextTextDecoration("###", "###");
        RenderTextClipped(text_pos, frame_bb.Max, label, label_end, &label_size);
    }
    else
    {
        // Unframed typed for tree nodes
        if (hovered || selected)
        {
            const ImU32 bg_col = GetColorU32((held && hovered) ? SegaUiCol_HeaderActive : hovered ? SegaUiCol_HeaderHovered : SegaUiCol_Header);
            RenderFrame(frame_bb.Min, frame_bb.Max, bg_col, false);
        }
        RenderNavHighlight(frame_bb, id, nav_highlight_flags);
        if (flags & SegaUiTreeNodeFlags_Bullet)
            RenderBullet(window->DrawList, ImVec2(text_pos.x - text_offset_x * 0.5f, text_pos.y + g.FontSize * 0.5f), text_col);
        else if (!is_leaf)
            RenderArrow(window->DrawList, ImVec2(text_pos.x - text_offset_x + padding.x, text_pos.y + g.FontSize * 0.15f), text_col, is_open ? SegaUiDir_Down : SegaUiDir_Right, 0.70f);
        if (g.LogEnabled)
            LogSetNextTextDecoration(">", NULL);
        RenderText(text_pos, label, label_end, false);
    }

    if (is_open && !(flags & SegaUiTreeNodeFlags_NoTreePushOnOpen))
        TreePushOverrideID(id);
    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags | (is_leaf ? 0 : SegaUiItemStatusFlags_Openable) | (is_open ? SegaUiItemStatusFlags_Opened : 0));
    return is_open;
}

void SegaUi::TreePush(const char* str_id)
{
    SegaUiWindow* window = GetCurrentWindow();
    Indent();
    window->DC.TreeDepth++;
    PushID(str_id);
}

void SegaUi::TreePush(const void* ptr_id)
{
    SegaUiWindow* window = GetCurrentWindow();
    Indent();
    window->DC.TreeDepth++;
    PushID(ptr_id);
}

void SegaUi::TreePushOverrideID(SegaUiID id)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    Indent();
    window->DC.TreeDepth++;
    PushOverrideID(id);
}

void SegaUi::TreePop()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    Unindent();

    window->DC.TreeDepth--;
    ImU32 tree_depth_mask = (1 << window->DC.TreeDepth);

    // Handle Left arrow to move to parent tree node (when SegaUiTreeNodeFlags_NavLeftJumpsBackHere is enabled)
    if (g.NavMoveDir == SegaUiDir_Left && g.NavWindow == window && NavMoveRequestButNoResultYet())
        if (g.NavIdIsAlive && (window->DC.TreeJumpToParentOnPopMask & tree_depth_mask))
        {
            SetNavID(window->IDStack.back(), g.NavLayer, 0, ImRect());
            NavMoveRequestCancel();
        }
    window->DC.TreeJumpToParentOnPopMask &= tree_depth_mask - 1;

    IM_ASSERT(window->IDStack.Size > 1); // There should always be 1 element in the IDStack (pushed during window creation). If this triggers you called TreePop/PopID too much.
    PopID();
}

// Horizontal distance preceding label when using TreeNode() or Bullet()
float SegaUi::GetTreeNodeToLabelSpacing()
{
    SegaUiContext& g = *GSegaUi;
    return g.FontSize + (g.Style.FramePadding.x * 2.0f);
}

// Set next TreeNode/CollapsingHeader open state.
void SegaUi::SetNextItemOpen(bool is_open, SegaUiCond cond)
{
    SegaUiContext& g = *GSegaUi;
    if (g.CurrentWindow->SkipItems)
        return;
    g.NextItemData.Flags |= SegaUiNextItemDataFlags_HasOpen;
    g.NextItemData.OpenVal = is_open;
    g.NextItemData.OpenCond = cond ? cond : SegaUiCond_Always;
}

// CollapsingHeader returns true when opened but do not indent nor push into the ID stack (because of the SegaUiTreeNodeFlags_NoTreePushOnOpen flag).
// This is basically the same as calling TreeNodeEx(label, SegaUiTreeNodeFlags_CollapsingHeader). You can remove the _NoTreePushOnOpen flag if you want behavior closer to normal TreeNode().
bool SegaUi::CollapsingHeader(const char* label, SegaUiTreeNodeFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    return TreeNodeBehavior(window->GetID(label), flags | SegaUiTreeNodeFlags_CollapsingHeader, label);
}

// p_visible == NULL                        : regular collapsing header
// p_visible != NULL && *p_visible == true  : show a small close button on the corner of the header, clicking the button will set *p_visible = false
// p_visible != NULL && *p_visible == false : do not show the header at all
// Do not mistake this with the Open state of the header itself, which you can adjust with SetNextItemOpen() or SegaUiTreeNodeFlags_DefaultOpen.
bool SegaUi::CollapsingHeader(const char* label, bool* p_visible, SegaUiTreeNodeFlags flags)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    if (p_visible && !*p_visible)
        return false;

    SegaUiID id = window->GetID(label);
    flags |= SegaUiTreeNodeFlags_CollapsingHeader;
    if (p_visible)
        flags |= SegaUiTreeNodeFlags_AllowItemOverlap | SegaUiTreeNodeFlags_ClipLabelForTrailingButton;
    bool is_open = TreeNodeBehavior(id, flags, label);
    if (p_visible != NULL)
    {
        // Create a small overlapping close button
        // FIXME: We can evolve this into user accessible helpers to add extra buttons on title bars, headers, etc.
        // FIXME: CloseButton can overlap into text, need find a way to clip the text somehow.
        SegaUiContext& g = *GSegaUi;
        SegaUiLastItemData last_item_backup = g.LastItemData;
        float button_size = g.FontSize;
        float button_x = ImMax(g.LastItemData.Rect.Min.x, g.LastItemData.Rect.Max.x - g.Style.FramePadding.x * 2.0f - button_size);
        float button_y = g.LastItemData.Rect.Min.y;
        SegaUiID close_button_id = GetIDWithSeed("#CLOSE", NULL, id);
        if (CloseButton(close_button_id, ImVec2(button_x, button_y)))
            *p_visible = false;
        g.LastItemData = last_item_backup;
    }

    return is_open;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: Selectable
//-------------------------------------------------------------------------
// - Selectable()
//-------------------------------------------------------------------------

struct selectable_state
{
    ImVec4 text;
};

bool SegaUi::Selectable(const char* label, bool selected, SegaUiSelectableFlags flags, const ImVec2& size_arg)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;

    // Submit label or explicit size to ItemSize(), whereas ItemAdd() will submit a larger/spanning rectangle.
    SegaUiID id = window->GetID(label);
    ImVec2 label_size = CalcTextSize(label, NULL, true);
    ImVec2 size(size_arg.x != 0.0f ? size_arg.x : label_size.x, size_arg.y != 0.0f ? size_arg.y : label_size.y);
    ImVec2 pos = window->DC.CursorPos;
    pos.y += window->DC.CurrLineTextBaseOffset;
    ItemSize(size, 0.0f);

    // Fill horizontal space
    // We don't support (size < 0.0f) in Selectable() because the ItemSpacing extension would make explicitly right-aligned sizes not visibly match other widgets.
    const bool span_all_columns = (flags & SegaUiSelectableFlags_SpanAllColumns) != 0;
    const float min_x = span_all_columns ? window->ParentWorkRect.Min.x : pos.x;
    const float max_x = span_all_columns ? window->ParentWorkRect.Max.x : window->WorkRect.Max.x;
    if (size_arg.x == 0.0f || (flags & SegaUiSelectableFlags_SpanAvailWidth))
        size.x = ImMax(label_size.x, max_x - min_x);

    // Text stays at the submission position, but bounding box may be extended on both sides
    const ImVec2 text_min = pos;
    const ImVec2 text_max(min_x + size.x, pos.y + size.y);

    // Selectables are meant to be tightly packed together with no click-gap, so we extend their box to cover spacing between selectable.
    ImRect bb(min_x, pos.y, text_max.x, text_max.y);
    if ((flags & SegaUiSelectableFlags_NoPadWithHalfSpacing) == 0)
    {
        const float spacing_x = span_all_columns ? 0.0f : style.ItemSpacing.x;
        const float spacing_y = style.ItemSpacing.y;
        const float spacing_L = IM_FLOOR(spacing_x * 0.50f);
        const float spacing_U = IM_FLOOR(spacing_y * 0.50f);
        bb.Min.x -= spacing_L;
        bb.Min.y -= spacing_U;
        bb.Max.x += (spacing_x - spacing_L);
        bb.Max.y += (spacing_y - spacing_U);
    }
    //if (g.IO.KeyCtrl) { GetForegroundDrawList()->AddRect(bb.Min, bb.Max, IM_COL32(0, 255, 0, 255)); }

    // Modify ClipRect for the ItemAdd(), faster than doing a PushColumnsBackground/PushTableBackground for every Selectable..
    const float backup_clip_rect_min_x = window->ClipRect.Min.x;
    const float backup_clip_rect_max_x = window->ClipRect.Max.x;
    if (span_all_columns)
    {
        window->ClipRect.Min.x = window->ParentWorkRect.Min.x;
        window->ClipRect.Max.x = window->ParentWorkRect.Max.x;
    }

    const bool disabled_item = (flags & SegaUiSelectableFlags_Disabled) != 0;
    const bool item_add = ItemAdd(bb, id, NULL, disabled_item ? SegaUiItemFlags_Disabled : SegaUiItemFlags_None);
    if (span_all_columns)
    {
        window->ClipRect.Min.x = backup_clip_rect_min_x;
        window->ClipRect.Max.x = backup_clip_rect_max_x;
    }

    if (!item_add)
        return false;

    const bool disabled_global = (g.CurrentItemFlags & SegaUiItemFlags_Disabled) != 0;
    if (disabled_item && !disabled_global) // Only testing this as an optimization
        BeginDisabled();

    // FIXME: We can standardize the behavior of those two, we could also keep the fast path of override ClipRect + full push on render only,
    // which would be advantageous since most selectable are not selected.
    if (span_all_columns && window->DC.CurrentColumns)
        PushColumnsBackground();
    else if (span_all_columns && g.CurrentTable)
        TablePushBackgroundChannel();

    // We use NoHoldingActiveID on menus so user can click and _hold_ on a menu then drag to browse child entries
    SegaUiButtonFlags button_flags = 0;
    if (flags & SegaUiSelectableFlags_NoHoldingActiveID) { button_flags |= SegaUiButtonFlags_NoHoldingActiveId; }
    if (flags & SegaUiSelectableFlags_NoSetKeyOwner) { button_flags |= SegaUiButtonFlags_NoSetKeyOwner; }
    if (flags & SegaUiSelectableFlags_SelectOnClick) { button_flags |= SegaUiButtonFlags_PressedOnClick; }
    if (flags & SegaUiSelectableFlags_SelectOnRelease) { button_flags |= SegaUiButtonFlags_PressedOnRelease; }
    if (flags & SegaUiSelectableFlags_AllowDoubleClick) { button_flags |= SegaUiButtonFlags_PressedOnClickRelease | SegaUiButtonFlags_PressedOnDoubleClick; }
    if (flags & SegaUiSelectableFlags_AllowItemOverlap) { button_flags |= SegaUiButtonFlags_AllowItemOverlap; }

    const bool was_selected = selected;
    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, button_flags);

    // Auto-select when moved into
    // - This will be more fully fleshed in the range-select branch
    // - This is not exposed as it won't nicely work with some user side handling of shift/control
    // - We cannot do 'if (g.NavJustMovedToId != id) { selected = false; pressed = was_selected; }' for two reasons
    //   - (1) it would require focus scope to be set, need exposing PushFocusScope() or equivalent (e.g. BeginSelection() calling PushFocusScope())
    //   - (2) usage will fail with clipped items
    //   The multi-select API aim to fix those issues, e.g. may be replaced with a BeginSelection() API.
    if ((flags & SegaUiSelectableFlags_SelectOnNav) && g.NavJustMovedToId != 0 && g.NavJustMovedToFocusScopeId == g.CurrentFocusScopeId)
        if (g.NavJustMovedToId == id)
            selected = pressed = true;

    // Update NavId when clicking or when Hovering (this doesn't happen on most widgets), so navigation can be resumed with gamepad/keyboard
    if (pressed || (hovered && (flags & SegaUiSelectableFlags_SetNavIdOnHover)))
    {
        if (!g.NavDisableMouseHover && g.NavWindow == window && g.NavLayer == window->DC.NavLayerCurrent)
        {
            SetNavID(id, window->DC.NavLayerCurrent, g.CurrentFocusScopeId, WindowRectAbsToRel(window, bb)); // (bb == NavRect)
            g.NavDisableHighlight = true;
        }
    }
    if (pressed)
        MarkItemEdited(id);

    if (flags & SegaUiSelectableFlags_AllowItemOverlap)
        SetItemAllowOverlap();

    // In this branch, Selectable() cannot toggle the selection so this will never trigger.
    if (selected != was_selected) //-V547
        g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_ToggledSelection;

    if (span_all_columns && window->DC.CurrentColumns)
        PopColumnsBackground();
    else if (span_all_columns && g.CurrentTable)
        TablePopBackgroundChannel();

    static std::map<SegaUiID, selectable_state> anim;
    auto it_anim = anim.find(id);

    if (it_anim == anim.end())
    {
        anim.insert({ id, selectable_state() });
        it_anim = anim.find(id);
    }

    it_anim->second.text = ImLerp(it_anim->second.text, selected ? c::accent : hovered ? c::text::text_hov : c::text::text, g.IO.DeltaTime * 6.f);

    PushFont(font::inter_bold);
    PushStyleColor(SegaUiCol_Text, GetColorU32(it_anim->second.text));
    RenderTextClipped(text_min, text_max, label, NULL, &label_size, style.SelectableTextAlign, &bb);
    PopStyleColor();
    PopFont();

    // Automatically close popups
    if (pressed && (window->Flags & SegaUiWindowFlags_Popup) && !(flags & SegaUiSelectableFlags_DontClosePopups) && !(g.LastItemData.InFlags & SegaUiItemFlags_SelectableDontClosePopup))
        CloseCurrentPopup();

    if (disabled_item && !disabled_global)
        EndDisabled();

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags);
    return pressed; //-V1020
}

bool SegaUi::Selectable(const char* label, bool* p_selected, SegaUiSelectableFlags flags, const ImVec2& size_arg)
{
    if (Selectable(label, *p_selected, flags, size_arg))
    {
        *p_selected = !*p_selected;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: ListBox
//-------------------------------------------------------------------------
// - BeginListBox()
// - EndListBox()
// - ListBox()
//-------------------------------------------------------------------------

// Tip: To have a list filling the entire window width, use size.x = -FLT_MIN and pass an non-visible label e.g. "##empty"
// Tip: If your vertical size is calculated from an item count (e.g. 10 * item_height) consider adding a fractional part to facilitate seeing scrolling boundaries (e.g. 10.25 * item_height).
bool SegaUi::BeginListBox(const char* label, const ImVec2& size_arg)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    const SegaUiStyle& style = g.Style;
    const SegaUiID id = GetID(label);
    const ImVec2 label_size = CalcTextSize(label, NULL, true);

    // Size default to hold ~7.25 items.
    // Fractional number of items helps seeing that we can scroll down/up without looking at scrollbar.
    ImVec2 size = ImFloor(CalcItemSize(size_arg, CalcItemWidth(), GetTextLineHeightWithSpacing() * 7.25f + style.FramePadding.y * 2.0f));
    ImVec2 frame_size = ImVec2(size.x, ImMax(size.y, label_size.y));
    ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + frame_size);
    ImRect bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f, 0.0f));
    g.NextItemData.ClearFlags();

    if (!IsRectVisible(bb.Min, bb.Max))
    {
        ItemSize(bb.GetSize(), style.FramePadding.y);
        ItemAdd(bb, 0, &frame_bb);
        return false;
    }

    // FIXME-OPT: We could omit the BeginGroup() if label_size.x but would need to omit the EndGroup() as well.
    BeginGroup();
    if (label_size.x > 0.0f)
    {
        ImVec2 label_pos = ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x, frame_bb.Min.y + style.FramePadding.y);
        RenderText(label_pos, label);
        window->DC.CursorMaxPos = ImMax(window->DC.CursorMaxPos, label_pos + label_size);
    }

    BeginChildFrame(id, frame_bb.GetSize());
    return true;
}

#ifndef SEGAUI_DISABLE_OBSOLETE_FUNCTIONS
// OBSOLETED in 1.81 (from February 2021)
bool SegaUi::ListBoxHeader(const char* label, int items_count, int height_in_items)
{
    // If height_in_items == -1, default height is maximum 7.
    SegaUiContext& g = *GSegaUi;
    float height_in_items_f = (height_in_items < 0 ? ImMin(items_count, 7) : height_in_items) + 0.25f;
    ImVec2 size;
    size.x = 0.0f;
    size.y = GetTextLineHeightWithSpacing() * height_in_items_f + g.Style.FramePadding.y * 2.0f;
    return BeginListBox(label, size);
}
#endif

void SegaUi::EndListBox()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    IM_ASSERT((window->Flags & SegaUiWindowFlags_ChildWindow) && "Mismatched BeginListBox/EndListBox calls. Did you test the return value of BeginListBox?");
    IM_UNUSED(window);

    EndChildFrame();
    EndGroup(); // This is only required to be able to do IsItemXXX query on the whole ListBox including label
}

bool SegaUi::ListBox(const char* label, int* current_item, const char* const items[], int items_count, int height_items)
{
    const bool value_changed = ListBox(label, current_item, Items_ArrayGetter, (void*)items, items_count, height_items);
    return value_changed;
}

// This is merely a helper around BeginListBox(), EndListBox().
// Considering using those directly to submit custom data or store selection differently.
bool SegaUi::ListBox(const char* label, int* current_item, bool (*items_getter)(void*, int, const char**), void* data, int items_count, int height_in_items)
{
    SegaUiContext& g = *GSegaUi;

    // Calculate size from "height_in_items"
    if (height_in_items < 0)
        height_in_items = ImMin(items_count, 7);
    float height_in_items_f = height_in_items + 0.25f;
    ImVec2 size(0.0f, ImFloor(GetTextLineHeightWithSpacing() * height_in_items_f + g.Style.FramePadding.y * 2.0f));

    if (!BeginListBox(label, size))
        return false;

    // Assume all items have even height (= 1 line of text). If you need items of different height,
    // you can create a custom version of ListBox() in your code without using the clipper.
    bool value_changed = false;
    SegaUiListClipper clipper;
    clipper.Begin(items_count, GetTextLineHeightWithSpacing()); // We know exactly our line height here so we pass it as a minor optimization, but generally you don't need to.
    while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++)
        {
            const char* item_text;
            if (!items_getter(data, i, &item_text))
                item_text = "*Unknown item*";

            PushID(i);
            const bool item_selected = (i == *current_item);
            if (Selectable(item_text, item_selected))
            {
                *current_item = i;
                value_changed = true;
            }
            if (item_selected)
                SetItemDefaultFocus();
            PopID();
        }
    EndListBox();

    if (value_changed)
        MarkItemEdited(g.LastItemData.ID);

    return value_changed;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: PlotLines, PlotHistogram
//-------------------------------------------------------------------------
// - PlotEx() [Internal]
// - PlotLines()
// - PlotHistogram()
//-------------------------------------------------------------------------
// Plot/Graph widgets are not very good.
// Consider writing your own, or using a third-party one, see:
// - ImPlot https://github.com/epezent/implot
// - others https://github.com/ocornut/imgui/wiki/Useful-Extensions
//-------------------------------------------------------------------------

int SegaUi::PlotEx(SegaUiPlotType plot_type, const char* label, float (*values_getter)(void* data, int idx), void* data, int values_count, int values_offset, const char* overlay_text, float scale_min, float scale_max, const ImVec2& size_arg)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return -1;

    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);

    const ImVec2 label_size = CalcTextSize(label, NULL, true);
    const ImVec2 frame_size = CalcItemSize(size_arg, CalcItemWidth(), label_size.y + style.FramePadding.y * 2.0f);

    const ImRect frame_bb(window->DC.CursorPos, window->DC.CursorPos + frame_size);
    const ImRect inner_bb(frame_bb.Min + style.FramePadding, frame_bb.Max - style.FramePadding);
    const ImRect total_bb(frame_bb.Min, frame_bb.Max + ImVec2(label_size.x > 0.0f ? style.ItemInnerSpacing.x + label_size.x : 0.0f, 0));
    ItemSize(total_bb, style.FramePadding.y);
    if (!ItemAdd(total_bb, 0, &frame_bb))
        return -1;
    const bool hovered = ItemHoverable(frame_bb, id);

    // Determine scale from values if not specified
    if (scale_min == FLT_MAX || scale_max == FLT_MAX)
    {
        float v_min = FLT_MAX;
        float v_max = -FLT_MAX;
        for (int i = 0; i < values_count; i++)
        {
            const float v = values_getter(data, i);
            if (v != v) // Ignore NaN values
                continue;
            v_min = ImMin(v_min, v);
            v_max = ImMax(v_max, v);
        }
        if (scale_min == FLT_MAX)
            scale_min = v_min;
        if (scale_max == FLT_MAX)
            scale_max = v_max;
    }

    RenderFrame(frame_bb.Min, frame_bb.Max, GetColorU32(SegaUiCol_FrameBg), true, style.FrameRounding);

    const int values_count_min = (plot_type == SegaUiPlotType_Lines) ? 2 : 1;
    int idx_hovered = -1;
    if (values_count >= values_count_min)
    {
        int res_w = ImMin((int)frame_size.x, values_count) + ((plot_type == SegaUiPlotType_Lines) ? -1 : 0);
        int item_count = values_count + ((plot_type == SegaUiPlotType_Lines) ? -1 : 0);

        // Tooltip on hover
        if (hovered && inner_bb.Contains(g.IO.MousePos))
        {
            const float t = ImClamp((g.IO.MousePos.x - inner_bb.Min.x) / (inner_bb.Max.x - inner_bb.Min.x), 0.0f, 0.9999f);
            const int v_idx = (int)(t * item_count);
            IM_ASSERT(v_idx >= 0 && v_idx < values_count);

            const float v0 = values_getter(data, (v_idx + values_offset) % values_count);
            const float v1 = values_getter(data, (v_idx + 1 + values_offset) % values_count);
            if (plot_type == SegaUiPlotType_Lines)
                SetTooltip("%d: %8.4g\n%d: %8.4g", v_idx, v0, v_idx + 1, v1);
            else if (plot_type == SegaUiPlotType_Histogram)
                SetTooltip("%d: %8.4g", v_idx, v0);
            idx_hovered = v_idx;
        }

        const float t_step = 1.0f / (float)res_w;
        const float inv_scale = (scale_min == scale_max) ? 0.0f : (1.0f / (scale_max - scale_min));

        float v0 = values_getter(data, (0 + values_offset) % values_count);
        float t0 = 0.0f;
        ImVec2 tp0 = ImVec2( t0, 1.0f - ImSaturate((v0 - scale_min) * inv_scale) );                       // Point in the normalized space of our target rectangle
        float histogram_zero_line_t = (scale_min * scale_max < 0.0f) ? (1 + scale_min * inv_scale) : (scale_min < 0.0f ? 0.0f : 1.0f);   // Where does the zero line stands

        const ImU32 col_base = GetColorU32((plot_type == SegaUiPlotType_Lines) ? SegaUiCol_PlotLines : SegaUiCol_PlotHistogram);
        const ImU32 col_hovered = GetColorU32((plot_type == SegaUiPlotType_Lines) ? SegaUiCol_PlotLinesHovered : SegaUiCol_PlotHistogramHovered);

        for (int n = 0; n < res_w; n++)
        {
            const float t1 = t0 + t_step;
            const int v1_idx = (int)(t0 * item_count + 0.5f);
            IM_ASSERT(v1_idx >= 0 && v1_idx < values_count);
            const float v1 = values_getter(data, (v1_idx + values_offset + 1) % values_count);
            const ImVec2 tp1 = ImVec2( t1, 1.0f - ImSaturate((v1 - scale_min) * inv_scale) );

            // NB: Draw calls are merged together by the DrawList system. Still, we should render our batch are lower level to save a bit of CPU.
            ImVec2 pos0 = ImLerp(inner_bb.Min, inner_bb.Max, tp0);
            ImVec2 pos1 = ImLerp(inner_bb.Min, inner_bb.Max, (plot_type == SegaUiPlotType_Lines) ? tp1 : ImVec2(tp1.x, histogram_zero_line_t));
            if (plot_type == SegaUiPlotType_Lines)
            {
                window->DrawList->AddLine(pos0, pos1, idx_hovered == v1_idx ? col_hovered : col_base);
            }
            else if (plot_type == SegaUiPlotType_Histogram)
            {
                if (pos1.x >= pos0.x + 2.0f)
                    pos1.x -= 1.0f;
                window->DrawList->AddRectFilled(pos0, pos1, idx_hovered == v1_idx ? col_hovered : col_base);
            }

            t0 = t1;
            tp0 = tp1;
        }
    }

    // Text overlay
    if (overlay_text)
        RenderTextClipped(ImVec2(frame_bb.Min.x, frame_bb.Min.y + style.FramePadding.y), frame_bb.Max, overlay_text, NULL, NULL, ImVec2(0.5f, 0.0f));

    if (label_size.x > 0.0f)
        RenderText(ImVec2(frame_bb.Max.x + style.ItemInnerSpacing.x, inner_bb.Min.y), label);

    // Return hovered index or -1 if none are hovered.
    // This is currently not exposed in the public API because we need a larger redesign of the whole thing, but in the short-term we are making it available in PlotEx().
    return idx_hovered;
}

struct SegaUiPlotArrayGetterData
{
    const float* Values;
    int Stride;

    SegaUiPlotArrayGetterData(const float* values, int stride) { Values = values; Stride = stride; }
};

static float Plot_ArrayGetter(void* data, int idx)
{
    SegaUiPlotArrayGetterData* plot_data = (SegaUiPlotArrayGetterData*)data;
    const float v = *(const float*)(const void*)((const unsigned char*)plot_data->Values + (size_t)idx * plot_data->Stride);
    return v;
}

void SegaUi::PlotLines(const char* label, const float* values, int values_count, int values_offset, const char* overlay_text, float scale_min, float scale_max, ImVec2 graph_size, int stride)
{
    SegaUiPlotArrayGetterData data(values, stride);
    PlotEx(SegaUiPlotType_Lines, label, &Plot_ArrayGetter, (void*)&data, values_count, values_offset, overlay_text, scale_min, scale_max, graph_size);
}

void SegaUi::PlotLines(const char* label, float (*values_getter)(void* data, int idx), void* data, int values_count, int values_offset, const char* overlay_text, float scale_min, float scale_max, ImVec2 graph_size)
{
    PlotEx(SegaUiPlotType_Lines, label, values_getter, data, values_count, values_offset, overlay_text, scale_min, scale_max, graph_size);
}

void SegaUi::PlotHistogram(const char* label, const float* values, int values_count, int values_offset, const char* overlay_text, float scale_min, float scale_max, ImVec2 graph_size, int stride)
{
    SegaUiPlotArrayGetterData data(values, stride);
    PlotEx(SegaUiPlotType_Histogram, label, &Plot_ArrayGetter, (void*)&data, values_count, values_offset, overlay_text, scale_min, scale_max, graph_size);
}

void SegaUi::PlotHistogram(const char* label, float (*values_getter)(void* data, int idx), void* data, int values_count, int values_offset, const char* overlay_text, float scale_min, float scale_max, ImVec2 graph_size)
{
    PlotEx(SegaUiPlotType_Histogram, label, values_getter, data, values_count, values_offset, overlay_text, scale_min, scale_max, graph_size);
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: Value helpers
// Those is not very useful, legacy API.
//-------------------------------------------------------------------------
// - Value()
//-------------------------------------------------------------------------

void SegaUi::Value(const char* prefix, bool b)
{
    Text("%s: %s", prefix, (b ? "true" : "false"));
}

void SegaUi::Value(const char* prefix, int v)
{
    Text("%s: %d", prefix, v);
}

void SegaUi::Value(const char* prefix, unsigned int v)
{
    Text("%s: %d", prefix, v);
}

void SegaUi::Value(const char* prefix, float v, const char* float_format)
{
    if (float_format)
    {
        char fmt[64];
        ImFormatString(fmt, IM_ARRAYSIZE(fmt), "%%s: %s", float_format);
        Text(fmt, prefix, v);
    }
    else
    {
        Text("%s: %.3f", prefix, v);
    }
}

//-------------------------------------------------------------------------
// [SECTION] MenuItem, BeginMenu, EndMenu, etc.
//-------------------------------------------------------------------------
// - SegaUiMenuColumns [Internal]
// - BeginMenuBar()
// - EndMenuBar()
// - BeginMainMenuBar()
// - EndMainMenuBar()
// - BeginMenu()
// - EndMenu()
// - MenuItemEx() [Internal]
// - MenuItem()
//-------------------------------------------------------------------------

// Helpers for internal use
void SegaUiMenuColumns::Update(float spacing, bool window_reappearing)
{
    if (window_reappearing)
        memset(Widths, 0, sizeof(Widths));
    Spacing = (ImU16)spacing;
    CalcNextTotalWidth(true);
    memset(Widths, 0, sizeof(Widths));
    TotalWidth = NextTotalWidth;
    NextTotalWidth = 0;
}

void SegaUiMenuColumns::CalcNextTotalWidth(bool update_offsets)
{
    ImU16 offset = 0;
    bool want_spacing = false;
    for (int i = 0; i < IM_ARRAYSIZE(Widths); i++)
    {
        ImU16 width = Widths[i];
        if (want_spacing && width > 0)
            offset += Spacing;
        want_spacing |= (width > 0);
        if (update_offsets)
        {
            if (i == 1) { OffsetLabel = offset; }
            if (i == 2) { OffsetShortcut = offset; }
            if (i == 3) { OffsetMark = offset; }
        }
        offset += width;
    }
    NextTotalWidth = offset;
}

float SegaUiMenuColumns::DeclColumns(float w_icon, float w_label, float w_shortcut, float w_mark)
{
    Widths[0] = ImMax(Widths[0], (ImU16)w_icon);
    Widths[1] = ImMax(Widths[1], (ImU16)w_label);
    Widths[2] = ImMax(Widths[2], (ImU16)w_shortcut);
    Widths[3] = ImMax(Widths[3], (ImU16)w_mark);
    CalcNextTotalWidth(false);
    return (float)ImMax(TotalWidth, NextTotalWidth);
}

// FIXME: Provided a rectangle perhaps e.g. a BeginMenuBarEx() could be used anywhere..
// Currently the main responsibility of this function being to setup clip-rect + horizontal layout + menu navigation layer.
// Ideally we also want this to be responsible for claiming space out of the main window scrolling rectangle, in which case SegaUiWindowFlags_MenuBar will become unnecessary.
// Then later the same system could be used for multiple menu-bars, scrollbars, side-bars.
bool SegaUi::BeginMenuBar()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;
    if (!(window->Flags & SegaUiWindowFlags_MenuBar))
        return false;

    IM_ASSERT(!window->DC.MenuBarAppending);
    BeginGroup(); // Backup position on layer 0 // FIXME: Misleading to use a group for that backup/restore
    PushID("##menubar");

    // We don't clip with current window clipping rectangle as it is already set to the area below. However we clip with window full rect.
    // We remove 1 worth of rounding to Max.x to that text in long menus and small windows don't tend to display over the lower-right rounded area, which looks particularly glitchy.
    ImRect bar_rect = window->MenuBarRect();
    ImRect clip_rect(IM_ROUND(bar_rect.Min.x + window->WindowBorderSize), IM_ROUND(bar_rect.Min.y + window->WindowBorderSize), IM_ROUND(ImMax(bar_rect.Min.x, bar_rect.Max.x - ImMax(window->WindowRounding, window->WindowBorderSize))), IM_ROUND(bar_rect.Max.y));
    clip_rect.ClipWith(window->OuterRectClipped);
    PushClipRect(clip_rect.Min, clip_rect.Max, false);

    // We overwrite CursorMaxPos because BeginGroup sets it to CursorPos (essentially the .EmitItem hack in EndMenuBar() would need something analogous here, maybe a BeginGroupEx() with flags).
    window->DC.CursorPos = window->DC.CursorMaxPos = ImVec2(bar_rect.Min.x + window->DC.MenuBarOffset.x, bar_rect.Min.y + window->DC.MenuBarOffset.y);
    window->DC.LayoutType = SegaUiLayoutType_Horizontal;
    window->DC.IsSameLine = false;
    window->DC.NavLayerCurrent = SegaUiNavLayer_Menu;
    window->DC.MenuBarAppending = true;
    AlignTextToFramePadding();
    return true;
}

void SegaUi::EndMenuBar()
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return;
    SegaUiContext& g = *GSegaUi;

    // Nav: When a move request within one of our child menu failed, capture the request to navigate among our siblings.
    if (NavMoveRequestButNoResultYet() && (g.NavMoveDir == SegaUiDir_Left || g.NavMoveDir == SegaUiDir_Right) && (g.NavWindow->Flags & SegaUiWindowFlags_ChildMenu))
    {
        // Try to find out if the request is for one of our child menu
        SegaUiWindow* nav_earliest_child = g.NavWindow;
        while (nav_earliest_child->ParentWindow && (nav_earliest_child->ParentWindow->Flags & SegaUiWindowFlags_ChildMenu))
            nav_earliest_child = nav_earliest_child->ParentWindow;
        if (nav_earliest_child->ParentWindow == window && nav_earliest_child->DC.ParentLayoutType == SegaUiLayoutType_Horizontal && (g.NavMoveFlags & SegaUiNavMoveFlags_Forwarded) == 0)
        {
            // To do so we claim focus back, restore NavId and then process the movement request for yet another frame.
            // This involve a one-frame delay which isn't very problematic in this situation. We could remove it by scoring in advance for multiple window (probably not worth bothering)
            const SegaUiNavLayer layer = SegaUiNavLayer_Menu;
            IM_ASSERT(window->DC.NavLayersActiveMaskNext & (1 << layer)); // Sanity check (FIXME: Seems unnecessary)
            FocusWindow(window);
            SetNavID(window->NavLastIds[layer], layer, 0, window->NavRectRel[layer]);
            g.NavDisableHighlight = true; // Hide highlight for the current frame so we don't see the intermediary selection.
            g.NavDisableMouseHover = g.NavMousePosDirty = true;
            NavMoveRequestForward(g.NavMoveDir, g.NavMoveClipDir, g.NavMoveFlags, g.NavMoveScrollFlags); // Repeat
        }
    }

    IM_MSVC_WARNING_SUPPRESS(6011); // Static Analysis false positive "warning C6011: Dereferencing NULL pointer 'window'"
    IM_ASSERT(window->Flags & SegaUiWindowFlags_MenuBar);
    IM_ASSERT(window->DC.MenuBarAppending);
    PopClipRect();
    PopID();
    window->DC.MenuBarOffset.x = window->DC.CursorPos.x - window->Pos.x; // Save horizontal position so next append can reuse it. This is kinda equivalent to a per-layer CursorPos.
    g.GroupStack.back().EmitItem = false;
    EndGroup(); // Restore position on layer 0
    window->DC.LayoutType = SegaUiLayoutType_Vertical;
    window->DC.IsSameLine = false;
    window->DC.NavLayerCurrent = SegaUiNavLayer_Main;
    window->DC.MenuBarAppending = false;
}

// Important: calling order matters!
// FIXME: Somehow overlapping with docking tech.
// FIXME: The "rect-cut" aspect of this could be formalized into a lower-level helper (rect-cut: https://halt.software/dead-simple-layouts)
bool SegaUi::BeginViewportSideBar(const char* name, SegaUiViewport* viewport_p, SegaUiDir dir, float axis_size, SegaUiWindowFlags window_flags)
{
    IM_ASSERT(dir != SegaUiDir_None);

    SegaUiWindow* bar_window = FindWindowByName(name);
    if (bar_window == NULL || bar_window->BeginCount == 0)
    {
        // Calculate and set window size/position
        SegaUiViewportP* viewport = (SegaUiViewportP*)(void*)(viewport_p ? viewport_p : GetMainViewport());
        ImRect avail_rect = viewport->GetBuildWorkRect();
        SegaUiAxis axis = (dir == SegaUiDir_Up || dir == SegaUiDir_Down) ? SegaUiAxis_Y : SegaUiAxis_X;
        ImVec2 pos = avail_rect.Min;
        if (dir == SegaUiDir_Right || dir == SegaUiDir_Down)
            pos[axis] = avail_rect.Max[axis] - axis_size;
        ImVec2 size = avail_rect.GetSize();
        size[axis] = axis_size;
        SetNextWindowPos(pos);
        SetNextWindowSize(size);

        // Report our size into work area (for next frame) using actual window size
        if (dir == SegaUiDir_Up || dir == SegaUiDir_Left)
            viewport->BuildWorkOffsetMin[axis] += axis_size;
        else if (dir == SegaUiDir_Down || dir == SegaUiDir_Right)
            viewport->BuildWorkOffsetMax[axis] -= axis_size;
    }

    window_flags |= SegaUiWindowFlags_NoTitleBar | SegaUiWindowFlags_NoResize | SegaUiWindowFlags_NoMove;

    // Create window
    PushStyleColor(SegaUiCol_WindowShadow, ImVec4(0, 0, 0, 0));
    PushStyleVar(SegaUiStyleVar_WindowRounding, 0.0f);
    PushStyleVar(SegaUiStyleVar_WindowMinSize, ImVec2(0, 0)); // Lift normal size constraint
    bool is_open = Begin(name, NULL, window_flags);
    PopStyleVar(2);
    PopStyleColor();

    return is_open;
}

bool SegaUi::BeginMainMenuBar()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiViewportP* viewport = (SegaUiViewportP*)(void*)GetMainViewport();

    // For the main menu bar, which cannot be moved, we honor g.Style.DisplaySafeAreaPadding to ensure text can be visible on a TV set.
    // FIXME: This could be generalized as an opt-in way to clamp window->DC.CursorStartPos to avoid SafeArea?
    // FIXME: Consider removing support for safe area down the line... it's messy. Nowadays consoles have support for TV calibration in OS settings.
    g.NextWindowData.MenuBarOffsetMinVal = ImVec2(g.Style.DisplaySafeAreaPadding.x, ImMax(g.Style.DisplaySafeAreaPadding.y - g.Style.FramePadding.y, 0.0f));
    SegaUiWindowFlags window_flags = SegaUiWindowFlags_NoScrollbar | SegaUiWindowFlags_NoSavedSettings | SegaUiWindowFlags_MenuBar;
    float height = GetFrameHeight();
    bool is_open = BeginViewportSideBar("##MainMenuBar", viewport, SegaUiDir_Up, height, window_flags);
    g.NextWindowData.MenuBarOffsetMinVal = ImVec2(0.0f, 0.0f);

    if (is_open)
        BeginMenuBar();
    else
        End();
    return is_open;
}

void SegaUi::EndMainMenuBar()
{
    EndMenuBar();

    // When the user has left the menu layer (typically: closed menus through activation of an item), we restore focus to the previous window
    // FIXME: With this strategy we won't be able to restore a NULL focus.
    SegaUiContext& g = *GSegaUi;
    if (g.CurrentWindow == g.NavWindow && g.NavLayer == SegaUiNavLayer_Main && !g.NavAnyRequest)
        FocusTopMostWindowUnderOne(g.NavWindow, NULL, NULL, SegaUiFocusRequestFlags_UnlessBelowModal | SegaUiFocusRequestFlags_RestoreFocusedChild);

    End();
}

static bool IsRootOfOpenMenuSet()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if ((g.OpenPopupStack.Size <= g.BeginPopupStack.Size) || (window->Flags & SegaUiWindowFlags_ChildMenu))
        return false;

    // Initially we used 'upper_popup->OpenParentId == window->IDStack.back()' to differentiate multiple menu sets from each others
    // (e.g. inside menu bar vs loose menu items) based on parent ID.
    // This would however prevent the use of e.g. PushID() user code submitting menus.
    // Previously this worked between popup and a first child menu because the first child menu always had the _ChildWindow flag,
    // making hovering on parent popup possible while first child menu was focused - but this was generally a bug with other side effects.
    // Instead we don't treat Popup specifically (in order to consistently support menu features in them), maybe the first child menu of a Popup
    // doesn't have the _ChildWindow flag, and we rely on this IsRootOfOpenMenuSet() check to allow hovering between root window/popup and first child menu.
    // In the end, lack of ID check made it so we could no longer differentiate between separate menu sets. To compensate for that, we at least check parent window nav layer.
    // This fixes the most common case of menu opening on hover when moving between window content and menu bar. Multiple different menu sets in same nav layer would still
    // open on hover, but that should be a lesser problem, because if such menus are close in proximity in window content then it won't feel weird and if they are far apart
    // it likely won't be a problem anyone runs into.
    const SegaUiPopupData* upper_popup = &g.OpenPopupStack[g.BeginPopupStack.Size];
    if (window->DC.NavLayerCurrent != upper_popup->ParentNavLayer)
        return false;
    return upper_popup->Window && (upper_popup->Window->Flags & SegaUiWindowFlags_ChildMenu) && SegaUi::IsWindowChildOf(upper_popup->Window, window, true);
}

bool SegaUi::BeginMenuEx(const char* label, const char* icon, bool enabled)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    const SegaUiStyle& style = g.Style;
    const SegaUiID id = window->GetID(label);
    bool menu_is_open = IsPopupOpen(id, SegaUiPopupFlags_None);

    // Sub-menus are ChildWindow so that mouse can be hovering across them (otherwise top-most popup menu would steal focus and not allow hovering on parent menu)
    // The first menu in a hierarchy isn't so hovering doesn't get across (otherwise e.g. resizing borders with SegaUiButtonFlags_FlattenChildren would react), but top-most BeginMenu() will bypass that limitation.
    SegaUiWindowFlags window_flags = SegaUiWindowFlags_ChildMenu | SegaUiWindowFlags_AlwaysAutoResize | SegaUiWindowFlags_NoMove | SegaUiWindowFlags_NoTitleBar | SegaUiWindowFlags_NoSavedSettings | SegaUiWindowFlags_NoNavFocus;
    if (window->Flags & SegaUiWindowFlags_ChildMenu)
        window_flags |= SegaUiWindowFlags_ChildWindow;

    // If a menu with same the ID was already submitted, we will append to it, matching the behavior of Begin().
    // We are relying on a O(N) search - so O(N log N) over the frame - which seems like the most efficient for the expected small amount of BeginMenu() calls per frame.
    // If somehow this is ever becoming a problem we can switch to use e.g. SegaUiStorage mapping key to last frame used.
    if (g.MenusIdSubmittedThisFrame.contains(id))
    {
        if (menu_is_open)
            menu_is_open = BeginPopupEx(id, window_flags); // menu_is_open can be 'false' when the popup is completely clipped (e.g. zero size display)
        else
            g.NextWindowData.ClearFlags();          // we behave like Begin() and need to consume those values
        return menu_is_open;
    }

    // Tag menu as used. Next time BeginMenu() with same ID is called it will append to existing menu
    g.MenusIdSubmittedThisFrame.push_back(id);

    ImVec2 label_size = CalcTextSize(label, NULL, true);

    // Odd hack to allow hovering across menus of a same menu-set (otherwise we wouldn't be able to hover parent without always being a Child window)
    // This is only done for items for the menu set and not the full parent window.
    const bool menuset_is_open = IsRootOfOpenMenuSet();
    if (menuset_is_open)
        PushItemFlag(SegaUiItemFlags_NoWindowHoverableCheck, true);

    // The reference position stored in popup_pos will be used by Begin() to find a suitable position for the child menu,
    // However the final position is going to be different! It is chosen by FindBestWindowPosForPopup().
    // e.g. Menus tend to overlap each other horizontally to amplify relative Z-ordering.
    ImVec2 popup_pos, pos = window->DC.CursorPos;
    PushID(label);
    if (!enabled)
        BeginDisabled();
    const SegaUiMenuColumns* offsets = &window->DC.MenuColumns;
    bool pressed;

    // We use SegaUiSelectableFlags_NoSetKeyOwner to allow down on one menu item, move, up on another.
    const SegaUiSelectableFlags selectable_flags = SegaUiSelectableFlags_NoHoldingActiveID | SegaUiSelectableFlags_NoSetKeyOwner | SegaUiSelectableFlags_SelectOnClick | SegaUiSelectableFlags_DontClosePopups;
    if (window->DC.LayoutType == SegaUiLayoutType_Horizontal)
    {
        // Menu inside an horizontal menu bar
        // Selectable extend their highlight by half ItemSpacing in each direction.
        // For ChildMenu, the popup position will be overwritten by the call to FindBestWindowPosForPopup() in Begin()
        popup_pos = ImVec2(pos.x - 1.0f - IM_FLOOR(style.ItemSpacing.x * 0.5f), pos.y - style.FramePadding.y + window->MenuBarHeight());
        window->DC.CursorPos.x += IM_FLOOR(style.ItemSpacing.x * 0.5f);
        PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x * 2.0f, style.ItemSpacing.y));
        float w = label_size.x;
        ImVec2 text_pos(window->DC.CursorPos.x + offsets->OffsetLabel, window->DC.CursorPos.y + window->DC.CurrLineTextBaseOffset);
        pressed = Selectable("", menu_is_open, selectable_flags, ImVec2(w, label_size.y));
        RenderText(text_pos, label);
        PopStyleVar();
        window->DC.CursorPos.x += IM_FLOOR(style.ItemSpacing.x * (-1.0f + 0.5f)); // -1 spacing to compensate the spacing added when Selectable() did a SameLine(). It would also work to call SameLine() ourselves after the PopStyleVar().
    }
    else
    {
        // Menu inside a regular/vertical menu
        // (In a typical menu window where all items are BeginMenu() or MenuItem() calls, extra_w will always be 0.0f.
        //  Only when they are other items sticking out we're going to add spacing, yet only register minimum width into the layout system.
        popup_pos = ImVec2(pos.x, pos.y - style.WindowPadding.y);
        float icon_w = (icon && icon[0]) ? CalcTextSize(icon, NULL).x : 0.0f;
        float checkmark_w = IM_FLOOR(g.FontSize * 1.20f);
        float min_w = window->DC.MenuColumns.DeclColumns(icon_w, label_size.x, 0.0f, checkmark_w); // Feedback to next frame
        float extra_w = ImMax(0.0f, GetContentRegionAvail().x - min_w);
        ImVec2 text_pos(window->DC.CursorPos.x + offsets->OffsetLabel, window->DC.CursorPos.y + window->DC.CurrLineTextBaseOffset);
        pressed = Selectable("", menu_is_open, selectable_flags | SegaUiSelectableFlags_SpanAvailWidth, ImVec2(min_w, label_size.y));
        RenderText(text_pos, label);
        if (icon_w > 0.0f)
            RenderText(pos + ImVec2(offsets->OffsetIcon, 0.0f), icon);
        RenderArrow(window->DrawList, pos + ImVec2(offsets->OffsetMark + extra_w + g.FontSize * 0.30f, 0.0f), GetColorU32(SegaUiCol_Text), SegaUiDir_Right);
    }
    if (!enabled)
        EndDisabled();

    const bool hovered = (g.HoveredId == id) && enabled && !g.NavDisableMouseHover;
    if (menuset_is_open)
        PopItemFlag();

    bool want_open = false;
    bool want_close = false;
    if (window->DC.LayoutType == SegaUiLayoutType_Vertical) // (window->Flags & (SegaUiWindowFlags_Popup|SegaUiWindowFlags_ChildMenu))
    {
        // Close menu when not hovering it anymore unless we are moving roughly in the direction of the menu
        // Implement http://bjk5.com/post/44698559168/breaking-down-amazons-mega-dropdown to avoid using timers, so menus feels more reactive.
        bool moving_toward_child_menu = false;
        SegaUiPopupData* child_popup = (g.BeginPopupStack.Size < g.OpenPopupStack.Size) ? &g.OpenPopupStack[g.BeginPopupStack.Size] : NULL; // Popup candidate (testing below)
        SegaUiWindow* child_menu_window = (child_popup && child_popup->Window && child_popup->Window->ParentWindow == window) ? child_popup->Window : NULL;
        if (g.HoveredWindow == window && child_menu_window != NULL)
        {
            float ref_unit = g.FontSize; // FIXME-DPI
            float child_dir = (window->Pos.x < child_menu_window->Pos.x) ? 1.0f : -1.0f;
            ImRect next_window_rect = child_menu_window->Rect();
            ImVec2 ta = (g.IO.MousePos - g.IO.MouseDelta);
            ImVec2 tb = (child_dir > 0.0f) ? next_window_rect.GetTL() : next_window_rect.GetTR();
            ImVec2 tc = (child_dir > 0.0f) ? next_window_rect.GetBL() : next_window_rect.GetBR();
            float extra = ImClamp(ImFabs(ta.x - tb.x) * 0.30f, ref_unit * 0.5f, ref_unit * 2.5f);   // add a bit of extra slack.
            ta.x += child_dir * -0.5f;
            tb.x += child_dir * ref_unit;
            tc.x += child_dir * ref_unit;
            tb.y = ta.y + ImMax((tb.y - extra) - ta.y, -ref_unit * 8.0f);                           // triangle has maximum height to limit the slope and the bias toward large sub-menus
            tc.y = ta.y + ImMin((tc.y + extra) - ta.y, +ref_unit * 8.0f);
            moving_toward_child_menu = ImTriangleContainsPoint(ta, tb, tc, g.IO.MousePos);
            //GetForegroundDrawList()->AddTriangleFilled(ta, tb, tc, moving_toward_child_menu ? IM_COL32(0,128,0,128) : IM_COL32(128,0,0,128)); // [DEBUG]
        }

        // The 'HovereWindow == window' check creates an inconsistency (e.g. moving away from menu slowly tends to hit same window, whereas moving away fast does not)
        // But we also need to not close the top-menu menu when moving over void. Perhaps we should extend the triangle check to a larger polygon.
        // (Remember to test this on BeginPopup("A")->BeginMenu("B") sequence which behaves slightly differently as B isn't a Child of A and hovering isn't shared.)
        if (menu_is_open && !hovered && g.HoveredWindow == window && !moving_toward_child_menu && !g.NavDisableMouseHover)
            want_close = true;

        // Open
        if (!menu_is_open && pressed) // Click/activate to open
            want_open = true;
        else if (!menu_is_open && hovered && !moving_toward_child_menu) // Hover to open
            want_open = true;
        if (g.NavId == id && g.NavMoveDir == SegaUiDir_Right) // Nav-Right to open
        {
            want_open = true;
            NavMoveRequestCancel();
        }
    }
    else
    {
        // Menu bar
        if (menu_is_open && pressed && menuset_is_open) // Click an open menu again to close it
        {
            want_close = true;
            want_open = menu_is_open = false;
        }
        else if (pressed || (hovered && menuset_is_open && !menu_is_open)) // First click to open, then hover to open others
        {
            want_open = true;
        }
        else if (g.NavId == id && g.NavMoveDir == SegaUiDir_Down) // Nav-Down to open
        {
            want_open = true;
            NavMoveRequestCancel();
        }
    }

    if (!enabled) // explicitly close if an open menu becomes disabled, facilitate users code a lot in pattern such as 'if (BeginMenu("options", has_object)) { ..use object.. }'
        want_close = true;
    if (want_close && IsPopupOpen(id, SegaUiPopupFlags_None))
        ClosePopupToLevel(g.BeginPopupStack.Size, true);

    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags | SegaUiItemStatusFlags_Openable | (menu_is_open ? SegaUiItemStatusFlags_Opened : 0));
    PopID();

    if (want_open && !menu_is_open && g.OpenPopupStack.Size > g.BeginPopupStack.Size)
    {
        // Don't reopen/recycle same menu level in the same frame, first close the other menu and yield for a frame.
        OpenPopup(label);
    }
    else if (want_open)
    {
        menu_is_open = true;
        OpenPopup(label);
    }

    if (menu_is_open)
    {
        SegaUiLastItemData last_item_in_parent = g.LastItemData;
        SetNextWindowPos(popup_pos, SegaUiCond_Always);                  // Note: misleading: the value will serve as reference for FindBestWindowPosForPopup(), not actual pos.
        PushStyleVar(SegaUiStyleVar_ChildRounding, style.PopupRounding); // First level will use _PopupRounding, subsequent will use _ChildRounding
        menu_is_open = BeginPopupEx(id, window_flags);                  // menu_is_open can be 'false' when the popup is completely clipped (e.g. zero size display)
        PopStyleVar();
        if (menu_is_open)
        {
            // Restore LastItemData so IsItemXXXX functions can work after BeginMenu()/EndMenu()
            // (This fixes using IsItemClicked() and IsItemHovered(), but IsItemHovered() also relies on its support for SegaUiItemFlags_NoWindowHoverableCheck)
            g.LastItemData = last_item_in_parent;
            if (g.HoveredWindow == window)
                g.LastItemData.StatusFlags |= SegaUiItemStatusFlags_HoveredWindow;
        }
    }
    else
    {
        g.NextWindowData.ClearFlags(); // We behave like Begin() and need to consume those values
    }

    return menu_is_open;
}

bool SegaUi::BeginMenu(const char* label, bool enabled)
{
    return BeginMenuEx(label, NULL, enabled);
}

void SegaUi::EndMenu()
{
    // Nav: When a left move request our menu failed, close ourselves.
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    IM_ASSERT(window->Flags & SegaUiWindowFlags_Popup);  // Mismatched BeginMenu()/EndMenu() calls
    SegaUiWindow* parent_window = window->ParentWindow;  // Should always be != NULL is we passed assert.
    if (window->BeginCount == window->BeginCountPreviousFrame)
        if (g.NavMoveDir == SegaUiDir_Left && NavMoveRequestButNoResultYet())
            if (g.NavWindow && (g.NavWindow->RootWindowForNav == window) && parent_window->DC.LayoutType == SegaUiLayoutType_Vertical)
            {
                ClosePopupToLevel(g.BeginPopupStack.Size - 1, true);
                NavMoveRequestCancel();
            }

    EndPopup();
}

bool SegaUi::MenuItemEx(const char* label, const char* icon, const char* shortcut, bool selected, bool enabled)
{
    SegaUiWindow* window = GetCurrentWindow();
    if (window->SkipItems)
        return false;

    SegaUiContext& g = *GSegaUi;
    SegaUiStyle& style = g.Style;
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 label_size = CalcTextSize(label, NULL, true);

    // See BeginMenuEx() for comments about this.
    const bool menuset_is_open = IsRootOfOpenMenuSet();
    if (menuset_is_open)
        PushItemFlag(SegaUiItemFlags_NoWindowHoverableCheck, true);

    // We've been using the equivalent of SegaUiSelectableFlags_SetNavIdOnHover on all Selectable() since early Nav system days (commit 43ee5d73),
    // but I am unsure whether this should be kept at all. For now moved it to be an opt-in feature used by menus only.
    bool pressed;
    PushID(label);
    if (!enabled)
        BeginDisabled();

    // We use SegaUiSelectableFlags_NoSetKeyOwner to allow down on one menu item, move, up on another.
    const SegaUiSelectableFlags selectable_flags = SegaUiSelectableFlags_SelectOnRelease | SegaUiSelectableFlags_NoSetKeyOwner | SegaUiSelectableFlags_SetNavIdOnHover;
    const SegaUiMenuColumns* offsets = &window->DC.MenuColumns;
    if (window->DC.LayoutType == SegaUiLayoutType_Horizontal)
    {
        // Mimic the exact layout spacing of BeginMenu() to allow MenuItem() inside a menu bar, which is a little misleading but may be useful
        // Note that in this situation: we don't render the shortcut, we render a highlight instead of the selected tick mark.
        float w = label_size.x;
        window->DC.CursorPos.x += IM_FLOOR(style.ItemSpacing.x * 0.5f);
        ImVec2 text_pos(window->DC.CursorPos.x + offsets->OffsetLabel, window->DC.CursorPos.y + window->DC.CurrLineTextBaseOffset);
        PushStyleVar(SegaUiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x * 2.0f, style.ItemSpacing.y));
        pressed = Selectable("", selected, selectable_flags, ImVec2(w, 0.0f));
        PopStyleVar();
        if (g.LastItemData.StatusFlags & SegaUiItemStatusFlags_Visible)
            RenderText(text_pos, label);
        window->DC.CursorPos.x += IM_FLOOR(style.ItemSpacing.x * (-1.0f + 0.5f)); // -1 spacing to compensate the spacing added when Selectable() did a SameLine(). It would also work to call SameLine() ourselves after the PopStyleVar().
    }
    else
    {
        // Menu item inside a vertical menu
        // (In a typical menu window where all items are BeginMenu() or MenuItem() calls, extra_w will always be 0.0f.
        //  Only when they are other items sticking out we're going to add spacing, yet only register minimum width into the layout system.
        float icon_w = (icon && icon[0]) ? CalcTextSize(icon, NULL).x : 0.0f;
        float shortcut_w = (shortcut && shortcut[0]) ? CalcTextSize(shortcut, NULL).x : 0.0f;
        float checkmark_w = IM_FLOOR(g.FontSize * 1.20f);
        float min_w = window->DC.MenuColumns.DeclColumns(icon_w, label_size.x, shortcut_w, checkmark_w); // Feedback for next frame
        float stretch_w = ImMax(0.0f, GetContentRegionAvail().x - min_w);
        pressed = Selectable("", false, selectable_flags | SegaUiSelectableFlags_SpanAvailWidth, ImVec2(min_w, label_size.y));
        if (g.LastItemData.StatusFlags & SegaUiItemStatusFlags_Visible)
        {
            RenderText(pos + ImVec2(offsets->OffsetLabel, 0.0f), label);
            if (icon_w > 0.0f)
                RenderText(pos + ImVec2(offsets->OffsetIcon, 0.0f), icon);
            if (shortcut_w > 0.0f)
            {
                PushStyleColor(SegaUiCol_Text, style.Colors[SegaUiCol_TextDisabled]);
                RenderText(pos + ImVec2(offsets->OffsetShortcut + stretch_w, 0.0f), shortcut, NULL, false);
                PopStyleColor();
            }
            if (selected)
                RenderCheckMark(window->DrawList, pos + ImVec2(offsets->OffsetMark + stretch_w + g.FontSize * 0.40f, g.FontSize * 0.134f * 0.5f), GetColorU32(SegaUiCol_Text), g.FontSize * 0.866f);
        }
    }
    SEGAUI_TEST_ENGINE_ITEM_INFO(g.LastItemData.ID, label, g.LastItemData.StatusFlags | SegaUiItemStatusFlags_Checkable | (selected ? SegaUiItemStatusFlags_Checked : 0));
    if (!enabled)
        EndDisabled();
    PopID();
    if (menuset_is_open)
        PopItemFlag();

    return pressed;
}

bool SegaUi::MenuItem(const char* label, const char* shortcut, bool selected, bool enabled)
{
    return MenuItemEx(label, NULL, shortcut, selected, enabled);
}

bool SegaUi::MenuItem(const char* label, const char* shortcut, bool* p_selected, bool enabled)
{
    if (MenuItemEx(label, NULL, shortcut, p_selected ? *p_selected : false, enabled))
    {
        if (p_selected)
            *p_selected = !*p_selected;
        return true;
    }
    return false;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: BeginTabBar, EndTabBar, etc.
//-------------------------------------------------------------------------
// - BeginTabBar()
// - BeginTabBarEx() [Internal]
// - EndTabBar()
// - TabBarLayout() [Internal]
// - TabBarCalcTabID() [Internal]
// - TabBarCalcMaxTabWidth() [Internal]
// - TabBarFindTabById() [Internal]
// - TabBarFindTabByOrder() [Internal]
// - TabBarGetCurrentTab() [Internal]
// - TabBarGetTabName() [Internal]
// - TabBarRemoveTab() [Internal]
// - TabBarCloseTab() [Internal]
// - TabBarScrollClamp() [Internal]
// - TabBarScrollToTab() [Internal]
// - TabBarQueueFocus() [Internal]
// - TabBarQueueReorder() [Internal]
// - TabBarProcessReorderFromMousePos() [Internal]
// - TabBarProcessReorder() [Internal]
// - TabBarScrollingButtons() [Internal]
// - TabBarTabListPopupButton() [Internal]
//-------------------------------------------------------------------------

struct SegaUiTabBarSection
{
    int                 TabCount;               // Number of tabs in this section.
    float               Width;                  // Sum of width of tabs in this section (after shrinking down)
    float               Spacing;                // Horizontal spacing at the end of the section.

    SegaUiTabBarSection() { memset(this, 0, sizeof(*this)); }
};

namespace SegaUi
{
    static void             TabBarLayout(SegaUiTabBar* tab_bar);
    static ImU32            TabBarCalcTabID(SegaUiTabBar* tab_bar, const char* label, SegaUiWindow* docked_window);
    static float            TabBarCalcMaxTabWidth();
    static float            TabBarScrollClamp(SegaUiTabBar* tab_bar, float scrolling);
    static void             TabBarScrollToTab(SegaUiTabBar* tab_bar, SegaUiID tab_id, SegaUiTabBarSection* sections);
    static SegaUiTabItem*    TabBarScrollingButtons(SegaUiTabBar* tab_bar);
    static SegaUiTabItem*    TabBarTabListPopupButton(SegaUiTabBar* tab_bar);
}

SegaUiTabBar::SegaUiTabBar()
{
    memset(this, 0, sizeof(*this));
    CurrFrameVisible = PrevFrameVisible = -1;
    LastTabItemIdx = -1;
}

static inline int TabItemGetSectionIdx(const SegaUiTabItem* tab)
{
    return (tab->Flags & SegaUiTabItemFlags_Leading) ? 0 : (tab->Flags & SegaUiTabItemFlags_Trailing) ? 2 : 1;
}

static int SEGAUI_CDECL TabItemComparerBySection(const void* lhs, const void* rhs)
{
    const SegaUiTabItem* a = (const SegaUiTabItem*)lhs;
    const SegaUiTabItem* b = (const SegaUiTabItem*)rhs;
    const int a_section = TabItemGetSectionIdx(a);
    const int b_section = TabItemGetSectionIdx(b);
    if (a_section != b_section)
        return a_section - b_section;
    return (int)(a->IndexDuringLayout - b->IndexDuringLayout);
}

static int SEGAUI_CDECL TabItemComparerByBeginOrder(const void* lhs, const void* rhs)
{
    const SegaUiTabItem* a = (const SegaUiTabItem*)lhs;
    const SegaUiTabItem* b = (const SegaUiTabItem*)rhs;
    return (int)(a->BeginOrder - b->BeginOrder);
}

static SegaUiTabBar* GetTabBarFromTabBarRef(const SegaUiPtrOrIndex& ref)
{
    SegaUiContext& g = *GSegaUi;
    return ref.Ptr ? (SegaUiTabBar*)ref.Ptr : g.TabBars.GetByIndex(ref.Index);
}

static SegaUiPtrOrIndex GetTabBarRefFromTabBar(SegaUiTabBar* tab_bar)
{
    SegaUiContext& g = *GSegaUi;
    if (g.TabBars.Contains(tab_bar))
        return SegaUiPtrOrIndex(g.TabBars.GetIndex(tab_bar));
    return SegaUiPtrOrIndex(tab_bar);
}

bool    SegaUi::BeginTabBar(const char* str_id, SegaUiTabBarFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    SegaUiID id = window->GetID(str_id);
    SegaUiTabBar* tab_bar = g.TabBars.GetOrAddByKey(id);
    ImRect tab_bar_bb = ImRect(window->DC.CursorPos.x, window->DC.CursorPos.y, window->WorkRect.Max.x, window->DC.CursorPos.y + g.FontSize + g.Style.FramePadding.y * 2);
    tab_bar->ID = id;
    return BeginTabBarEx(tab_bar, tab_bar_bb, flags | SegaUiTabBarFlags_IsFocused);
}

bool    SegaUi::BeginTabBarEx(SegaUiTabBar* tab_bar, const ImRect& tab_bar_bb, SegaUiTabBarFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    if ((flags & SegaUiTabBarFlags_DockNode) == 0)
        PushOverrideID(tab_bar->ID);

    // Add to stack
    g.CurrentTabBarStack.push_back(GetTabBarRefFromTabBar(tab_bar));
    g.CurrentTabBar = tab_bar;

    // Append with multiple BeginTabBar()/EndTabBar() pairs.
    tab_bar->BackupCursorPos = window->DC.CursorPos;
    if (tab_bar->CurrFrameVisible == g.FrameCount)
    {
        window->DC.CursorPos = ImVec2(tab_bar->BarRect.Min.x, tab_bar->BarRect.Max.y + tab_bar->ItemSpacingY);
        tab_bar->BeginCount++;
        return true;
    }

    // Ensure correct ordering when toggling SegaUiTabBarFlags_Reorderable flag, or when a new tab was added while being not reorderable
    if ((flags & SegaUiTabBarFlags_Reorderable) != (tab_bar->Flags & SegaUiTabBarFlags_Reorderable) || (tab_bar->TabsAddedNew && !(flags & SegaUiTabBarFlags_Reorderable)))
        ImQsort(tab_bar->Tabs.Data, tab_bar->Tabs.Size, sizeof(SegaUiTabItem), TabItemComparerByBeginOrder);
    tab_bar->TabsAddedNew = false;

    // Flags
    if ((flags & SegaUiTabBarFlags_FittingPolicyMask_) == 0)
        flags |= SegaUiTabBarFlags_FittingPolicyDefault_;

    tab_bar->Flags = flags;
    tab_bar->BarRect = tab_bar_bb;
    tab_bar->WantLayout = true; // Layout will be done on the first call to ItemTab()
    tab_bar->PrevFrameVisible = tab_bar->CurrFrameVisible;
    tab_bar->CurrFrameVisible = g.FrameCount;
    tab_bar->PrevTabsContentsHeight = tab_bar->CurrTabsContentsHeight;
    tab_bar->CurrTabsContentsHeight = 0.0f;
    tab_bar->ItemSpacingY = g.Style.ItemSpacing.y;
    tab_bar->FramePadding = g.Style.FramePadding;
    tab_bar->TabsActiveCount = 0;
    tab_bar->LastTabItemIdx = -1;
    tab_bar->BeginCount = 1;

    // Set cursor pos in a way which only be used in the off-chance the user erroneously submits item before BeginTabItem(): items will overlap
    window->DC.CursorPos = ImVec2(tab_bar->BarRect.Min.x, tab_bar->BarRect.Max.y + tab_bar->ItemSpacingY);

    // Draw separator
    const ImU32 col = GetColorU32((flags & SegaUiTabBarFlags_IsFocused) ? SegaUiCol_TabActive : SegaUiCol_TabUnfocusedActive);
    const float y = tab_bar->BarRect.Max.y - 1.0f;
    {
        const float separator_min_x = tab_bar->BarRect.Min.x - IM_FLOOR(window->WindowPadding.x * 0.5f);
        const float separator_max_x = tab_bar->BarRect.Max.x + IM_FLOOR(window->WindowPadding.x * 0.5f);
        window->DrawList->AddLine(ImVec2(separator_min_x, y), ImVec2(separator_max_x, y), col, 1.0f);
    }
    return true;
}

void    SegaUi::EndTabBar()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return;

    SegaUiTabBar* tab_bar = g.CurrentTabBar;
    if (tab_bar == NULL)
    {
        IM_ASSERT_USER_ERROR(tab_bar != NULL, "Mismatched BeginTabBar()/EndTabBar()!");
        return;
    }

    // Fallback in case no TabItem have been submitted
    if (tab_bar->WantLayout)
        TabBarLayout(tab_bar);

    // Restore the last visible height if no tab is visible, this reduce vertical flicker/movement when a tabs gets removed without calling SetTabItemClosed().
    const bool tab_bar_appearing = (tab_bar->PrevFrameVisible + 1 < g.FrameCount);
    if (tab_bar->VisibleTabWasSubmitted || tab_bar->VisibleTabId == 0 || tab_bar_appearing)
    {
        tab_bar->CurrTabsContentsHeight = ImMax(window->DC.CursorPos.y - tab_bar->BarRect.Max.y, tab_bar->CurrTabsContentsHeight);
        window->DC.CursorPos.y = tab_bar->BarRect.Max.y + tab_bar->CurrTabsContentsHeight;
    }
    else
    {
        window->DC.CursorPos.y = tab_bar->BarRect.Max.y + tab_bar->PrevTabsContentsHeight;
    }
    if (tab_bar->BeginCount > 1)
        window->DC.CursorPos = tab_bar->BackupCursorPos;

    tab_bar->LastTabItemIdx = -1;
    if ((tab_bar->Flags & SegaUiTabBarFlags_DockNode) == 0)
        PopID();

    g.CurrentTabBarStack.pop_back();
    g.CurrentTabBar = g.CurrentTabBarStack.empty() ? NULL : GetTabBarFromTabBarRef(g.CurrentTabBarStack.back());
}

// Scrolling happens only in the central section (leading/trailing sections are not scrolling)
static float TabBarCalcScrollableWidth(SegaUiTabBar* tab_bar, SegaUiTabBarSection* sections)
{
    return tab_bar->BarRect.GetWidth() - sections[0].Width - sections[2].Width - sections[1].Spacing;
}

// This is called only once a frame before by the first call to ItemTab()
// The reason we're not calling it in BeginTabBar() is to leave a chance to the user to call the SetTabItemClosed() functions.
static void SegaUi::TabBarLayout(SegaUiTabBar* tab_bar)
{
    SegaUiContext& g = *GSegaUi;
    tab_bar->WantLayout = false;

    // Garbage collect by compacting list
    // Detect if we need to sort out tab list (e.g. in rare case where a tab changed section)
    int tab_dst_n = 0;
    bool need_sort_by_section = false;
    SegaUiTabBarSection sections[3]; // Layout sections: Leading, Central, Trailing
    for (int tab_src_n = 0; tab_src_n < tab_bar->Tabs.Size; tab_src_n++)
    {
        SegaUiTabItem* tab = &tab_bar->Tabs[tab_src_n];
        if (tab->LastFrameVisible < tab_bar->PrevFrameVisible || tab->WantClose)
        {
            // Remove tab
            if (tab_bar->VisibleTabId == tab->ID) { tab_bar->VisibleTabId = 0; }
            if (tab_bar->SelectedTabId == tab->ID) { tab_bar->SelectedTabId = 0; }
            if (tab_bar->NextSelectedTabId == tab->ID) { tab_bar->NextSelectedTabId = 0; }
            continue;
        }
        if (tab_dst_n != tab_src_n)
            tab_bar->Tabs[tab_dst_n] = tab_bar->Tabs[tab_src_n];

        tab = &tab_bar->Tabs[tab_dst_n];
        tab->IndexDuringLayout = (ImS16)tab_dst_n;

        // We will need sorting if tabs have changed section (e.g. moved from one of Leading/Central/Trailing to another)
        int curr_tab_section_n = TabItemGetSectionIdx(tab);
        if (tab_dst_n > 0)
        {
            SegaUiTabItem* prev_tab = &tab_bar->Tabs[tab_dst_n - 1];
            int prev_tab_section_n = TabItemGetSectionIdx(prev_tab);
            if (curr_tab_section_n == 0 && prev_tab_section_n != 0)
                need_sort_by_section = true;
            if (prev_tab_section_n == 2 && curr_tab_section_n != 2)
                need_sort_by_section = true;
        }

        sections[curr_tab_section_n].TabCount++;
        tab_dst_n++;
    }
    if (tab_bar->Tabs.Size != tab_dst_n)
        tab_bar->Tabs.resize(tab_dst_n);

    if (need_sort_by_section)
        ImQsort(tab_bar->Tabs.Data, tab_bar->Tabs.Size, sizeof(SegaUiTabItem), TabItemComparerBySection);

    // Calculate spacing between sections
    sections[0].Spacing = sections[0].TabCount > 0 && (sections[1].TabCount + sections[2].TabCount) > 0 ? g.Style.ItemInnerSpacing.x : 0.0f;
    sections[1].Spacing = sections[1].TabCount > 0 && sections[2].TabCount > 0 ? g.Style.ItemInnerSpacing.x : 0.0f;

    // Setup next selected tab
    SegaUiID scroll_to_tab_id = 0;
    if (tab_bar->NextSelectedTabId)
    {
        tab_bar->SelectedTabId = tab_bar->NextSelectedTabId;
        tab_bar->NextSelectedTabId = 0;
        scroll_to_tab_id = tab_bar->SelectedTabId;
    }

    // Process order change request (we could probably process it when requested but it's just saner to do it in a single spot).
    if (tab_bar->ReorderRequestTabId != 0)
    {
        if (TabBarProcessReorder(tab_bar))
            if (tab_bar->ReorderRequestTabId == tab_bar->SelectedTabId)
                scroll_to_tab_id = tab_bar->ReorderRequestTabId;
        tab_bar->ReorderRequestTabId = 0;
    }

    // Tab List Popup (will alter tab_bar->BarRect and therefore the available width!)
    const bool tab_list_popup_button = (tab_bar->Flags & SegaUiTabBarFlags_TabListPopupButton) != 0;
    if (tab_list_popup_button)
        if (SegaUiTabItem* tab_to_select = TabBarTabListPopupButton(tab_bar)) // NB: Will alter BarRect.Min.x!
            scroll_to_tab_id = tab_bar->SelectedTabId = tab_to_select->ID;

    // Leading/Trailing tabs will be shrink only if central one aren't visible anymore, so layout the shrink data as: leading, trailing, central
    // (whereas our tabs are stored as: leading, central, trailing)
    int shrink_buffer_indexes[3] = { 0, sections[0].TabCount + sections[2].TabCount, sections[0].TabCount };
    g.ShrinkWidthBuffer.resize(tab_bar->Tabs.Size);

    // Compute ideal tabs widths + store them into shrink buffer
    SegaUiTabItem* most_recently_selected_tab = NULL;
    int curr_section_n = -1;
    bool found_selected_tab_id = false;
    for (int tab_n = 0; tab_n < tab_bar->Tabs.Size; tab_n++)
    {
        SegaUiTabItem* tab = &tab_bar->Tabs[tab_n];
        IM_ASSERT(tab->LastFrameVisible >= tab_bar->PrevFrameVisible);

        if ((most_recently_selected_tab == NULL || most_recently_selected_tab->LastFrameSelected < tab->LastFrameSelected) && !(tab->Flags & SegaUiTabItemFlags_Button))
            most_recently_selected_tab = tab;
        if (tab->ID == tab_bar->SelectedTabId)
            found_selected_tab_id = true;
        if (scroll_to_tab_id == 0 && g.NavJustMovedToId == tab->ID)
            scroll_to_tab_id = tab->ID;

        // Refresh tab width immediately, otherwise changes of style e.g. style.FramePadding.x would noticeably lag in the tab bar.
        // Additionally, when using TabBarAddTab() to manipulate tab bar order we occasionally insert new tabs that don't have a width yet,
        // and we cannot wait for the next BeginTabItem() call. We cannot compute this width within TabBarAddTab() because font size depends on the active window.
        const char* tab_name = TabBarGetTabName(tab_bar, tab);
        const bool has_close_button_or_unsaved_marker = (tab->Flags & SegaUiTabItemFlags_NoCloseButton) == 0 || (tab->Flags & SegaUiTabItemFlags_UnsavedDocument);
        tab->ContentWidth = (tab->RequestedWidth >= 0.0f) ? tab->RequestedWidth : TabItemCalcSize(tab_name, has_close_button_or_unsaved_marker).x;

        int section_n = TabItemGetSectionIdx(tab);
        SegaUiTabBarSection* section = &sections[section_n];
        section->Width += tab->ContentWidth + (section_n == curr_section_n ? g.Style.ItemInnerSpacing.x : 0.0f);
        curr_section_n = section_n;

        // Store data so we can build an array sorted by width if we need to shrink tabs down
        IM_MSVC_WARNING_SUPPRESS(6385);
        SegaUiShrinkWidthItem* shrink_width_item = &g.ShrinkWidthBuffer[shrink_buffer_indexes[section_n]++];
        shrink_width_item->Index = tab_n;
        shrink_width_item->Width = shrink_width_item->InitialWidth = tab->ContentWidth;
        tab->Width = ImMax(tab->ContentWidth, 1.0f);
    }

    // Compute total ideal width (used for e.g. auto-resizing a window)
    tab_bar->WidthAllTabsIdeal = 0.0f;
    for (int section_n = 0; section_n < 3; section_n++)
        tab_bar->WidthAllTabsIdeal += sections[section_n].Width + sections[section_n].Spacing;

    // Horizontal scrolling buttons
    // (note that TabBarScrollButtons() will alter BarRect.Max.x)
    if ((tab_bar->WidthAllTabsIdeal > tab_bar->BarRect.GetWidth() && tab_bar->Tabs.Size > 1) && !(tab_bar->Flags & SegaUiTabBarFlags_NoTabListScrollingButtons) && (tab_bar->Flags & SegaUiTabBarFlags_FittingPolicyScroll))
        if (SegaUiTabItem* scroll_and_select_tab = TabBarScrollingButtons(tab_bar))
        {
            scroll_to_tab_id = scroll_and_select_tab->ID;
            if ((scroll_and_select_tab->Flags & SegaUiTabItemFlags_Button) == 0)
                tab_bar->SelectedTabId = scroll_to_tab_id;
        }

    // Shrink widths if full tabs don't fit in their allocated space
    float section_0_w = sections[0].Width + sections[0].Spacing;
    float section_1_w = sections[1].Width + sections[1].Spacing;
    float section_2_w = sections[2].Width + sections[2].Spacing;
    bool central_section_is_visible = (section_0_w + section_2_w) < tab_bar->BarRect.GetWidth();
    float width_excess;
    if (central_section_is_visible)
        width_excess = ImMax(section_1_w - (tab_bar->BarRect.GetWidth() - section_0_w - section_2_w), 0.0f); // Excess used to shrink central section
    else
        width_excess = (section_0_w + section_2_w) - tab_bar->BarRect.GetWidth(); // Excess used to shrink leading/trailing section

    // With SegaUiTabBarFlags_FittingPolicyScroll policy, we will only shrink leading/trailing if the central section is not visible anymore
    if (width_excess >= 1.0f && ((tab_bar->Flags & SegaUiTabBarFlags_FittingPolicyResizeDown) || !central_section_is_visible))
    {
        int shrink_data_count = (central_section_is_visible ? sections[1].TabCount : sections[0].TabCount + sections[2].TabCount);
        int shrink_data_offset = (central_section_is_visible ? sections[0].TabCount + sections[2].TabCount : 0);
        ShrinkWidths(g.ShrinkWidthBuffer.Data + shrink_data_offset, shrink_data_count, width_excess);

        // Apply shrunk values into tabs and sections
        for (int tab_n = shrink_data_offset; tab_n < shrink_data_offset + shrink_data_count; tab_n++)
        {
            SegaUiTabItem* tab = &tab_bar->Tabs[g.ShrinkWidthBuffer[tab_n].Index];
            float shrinked_width = IM_FLOOR(g.ShrinkWidthBuffer[tab_n].Width);
            if (shrinked_width < 0.0f)
                continue;

            shrinked_width = ImMax(1.0f, shrinked_width);
            int section_n = TabItemGetSectionIdx(tab);
            sections[section_n].Width -= (tab->Width - shrinked_width);
            tab->Width = shrinked_width;
        }
    }

    // Layout all active tabs
    int section_tab_index = 0;
    float tab_offset = 0.0f;
    tab_bar->WidthAllTabs = 0.0f;
    for (int section_n = 0; section_n < 3; section_n++)
    {
        SegaUiTabBarSection* section = &sections[section_n];
        if (section_n == 2)
            tab_offset = ImMin(ImMax(0.0f, tab_bar->BarRect.GetWidth() - section->Width), tab_offset);

        for (int tab_n = 0; tab_n < section->TabCount; tab_n++)
        {
            SegaUiTabItem* tab = &tab_bar->Tabs[section_tab_index + tab_n];
            tab->Offset = tab_offset;
            tab->NameOffset = -1;
            tab_offset += tab->Width + (tab_n < section->TabCount - 1 ? g.Style.ItemInnerSpacing.x : 0.0f);
        }
        tab_bar->WidthAllTabs += ImMax(section->Width + section->Spacing, 0.0f);
        tab_offset += section->Spacing;
        section_tab_index += section->TabCount;
    }

    // Clear name buffers
    tab_bar->TabsNames.Buf.resize(0);

    // If we have lost the selected tab, select the next most recently active one
    if (found_selected_tab_id == false)
        tab_bar->SelectedTabId = 0;
    if (tab_bar->SelectedTabId == 0 && tab_bar->NextSelectedTabId == 0 && most_recently_selected_tab != NULL)
        scroll_to_tab_id = tab_bar->SelectedTabId = most_recently_selected_tab->ID;

    // Lock in visible tab
    tab_bar->VisibleTabId = tab_bar->SelectedTabId;
    tab_bar->VisibleTabWasSubmitted = false;

    // Apply request requests
    if (scroll_to_tab_id != 0)
        TabBarScrollToTab(tab_bar, scroll_to_tab_id, sections);
    else if ((tab_bar->Flags & SegaUiTabBarFlags_FittingPolicyScroll) && IsMouseHoveringRect(tab_bar->BarRect.Min, tab_bar->BarRect.Max, true) && IsWindowContentHoverable(g.CurrentWindow))
    {
        const float wheel = g.IO.MouseWheelRequestAxisSwap ? g.IO.MouseWheel : g.IO.MouseWheelH;
        const SegaUiKey wheel_key = g.IO.MouseWheelRequestAxisSwap ? SegaUiKey_MouseWheelY : SegaUiKey_MouseWheelX;
        if (TestKeyOwner(wheel_key, tab_bar->ID) && wheel != 0.0f)
        {
            const float scroll_step = wheel * TabBarCalcScrollableWidth(tab_bar, sections) / 3.0f;
            tab_bar->ScrollingTargetDistToVisibility = 0.0f;
            tab_bar->ScrollingTarget = TabBarScrollClamp(tab_bar, tab_bar->ScrollingTarget - scroll_step);
        }
        SetKeyOwner(wheel_key, tab_bar->ID);
    }

    // Update scrolling
    tab_bar->ScrollingAnim = TabBarScrollClamp(tab_bar, tab_bar->ScrollingAnim);
    tab_bar->ScrollingTarget = TabBarScrollClamp(tab_bar, tab_bar->ScrollingTarget);
    if (tab_bar->ScrollingAnim != tab_bar->ScrollingTarget)
    {
        // Scrolling speed adjust itself so we can always reach our target in 1/3 seconds.
        // Teleport if we are aiming far off the visible line
        tab_bar->ScrollingSpeed = ImMax(tab_bar->ScrollingSpeed, 70.0f * g.FontSize);
        tab_bar->ScrollingSpeed = ImMax(tab_bar->ScrollingSpeed, ImFabs(tab_bar->ScrollingTarget - tab_bar->ScrollingAnim) / 0.3f);
        const bool teleport = (tab_bar->PrevFrameVisible + 1 < g.FrameCount) || (tab_bar->ScrollingTargetDistToVisibility > 10.0f * g.FontSize);
        tab_bar->ScrollingAnim = teleport ? tab_bar->ScrollingTarget : ImLinearSweep(tab_bar->ScrollingAnim, tab_bar->ScrollingTarget, g.IO.DeltaTime * tab_bar->ScrollingSpeed);
    }
    else
    {
        tab_bar->ScrollingSpeed = 0.0f;
    }
    tab_bar->ScrollingRectMinX = tab_bar->BarRect.Min.x + sections[0].Width + sections[0].Spacing;
    tab_bar->ScrollingRectMaxX = tab_bar->BarRect.Max.x - sections[2].Width - sections[1].Spacing;

    // Actual layout in host window (we don't do it in BeginTabBar() so as not to waste an extra frame)
    SegaUiWindow* window = g.CurrentWindow;
    window->DC.CursorPos = tab_bar->BarRect.Min;
    ItemSize(ImVec2(tab_bar->WidthAllTabs, tab_bar->BarRect.GetHeight()), tab_bar->FramePadding.y);
    window->DC.IdealMaxPos.x = ImMax(window->DC.IdealMaxPos.x, tab_bar->BarRect.Min.x + tab_bar->WidthAllTabsIdeal);
}

// Dockable windows uses Name/ID in the global namespace. Non-dockable items use the ID stack.
static ImU32   SegaUi::TabBarCalcTabID(SegaUiTabBar* tab_bar, const char* label, SegaUiWindow* docked_window)
{
    IM_ASSERT(docked_window == NULL); // master branch only
    IM_UNUSED(docked_window);
    if (tab_bar->Flags & SegaUiTabBarFlags_DockNode)
    {
        SegaUiID id = ImHashStr(label);
        KeepAliveID(id);
        return id;
    }
    else
    {
        SegaUiWindow* window = GSegaUi->CurrentWindow;
        return window->GetID(label);
    }
}

static float SegaUi::TabBarCalcMaxTabWidth()
{
    SegaUiContext& g = *GSegaUi;
    return g.FontSize * 20.0f;
}

SegaUiTabItem* SegaUi::TabBarFindTabByID(SegaUiTabBar* tab_bar, SegaUiID tab_id)
{
    if (tab_id != 0)
        for (int n = 0; n < tab_bar->Tabs.Size; n++)
            if (tab_bar->Tabs[n].ID == tab_id)
                return &tab_bar->Tabs[n];
    return NULL;
}

// Order = visible order, not submission order! (which is tab->BeginOrder)
SegaUiTabItem* SegaUi::TabBarFindTabByOrder(SegaUiTabBar* tab_bar, int order)
{
    if (order < 0 || order >= tab_bar->Tabs.Size)
        return NULL;
    return &tab_bar->Tabs[order];
}

SegaUiTabItem* SegaUi::TabBarGetCurrentTab(SegaUiTabBar* tab_bar)
{
    if (tab_bar->LastTabItemIdx <= 0 || tab_bar->LastTabItemIdx >= tab_bar->Tabs.Size)
        return NULL;
    return &tab_bar->Tabs[tab_bar->LastTabItemIdx];
}

const char* SegaUi::TabBarGetTabName(SegaUiTabBar* tab_bar, SegaUiTabItem* tab)
{
    if (tab->NameOffset == -1)
        return "N/A";
    IM_ASSERT(tab->NameOffset < tab_bar->TabsNames.Buf.Size);
    return tab_bar->TabsNames.Buf.Data + tab->NameOffset;
}

// The *TabId fields are already set by the docking system _before_ the actual TabItem was created, so we clear them regardless.
void SegaUi::TabBarRemoveTab(SegaUiTabBar* tab_bar, SegaUiID tab_id)
{
    if (SegaUiTabItem* tab = TabBarFindTabByID(tab_bar, tab_id))
        tab_bar->Tabs.erase(tab);
    if (tab_bar->VisibleTabId == tab_id)      { tab_bar->VisibleTabId = 0; }
    if (tab_bar->SelectedTabId == tab_id)     { tab_bar->SelectedTabId = 0; }
    if (tab_bar->NextSelectedTabId == tab_id) { tab_bar->NextSelectedTabId = 0; }
}

// Called on manual closure attempt
void SegaUi::TabBarCloseTab(SegaUiTabBar* tab_bar, SegaUiTabItem* tab)
{
    if (tab->Flags & SegaUiTabItemFlags_Button)
        return; // A button appended with TabItemButton().

    if (!(tab->Flags & SegaUiTabItemFlags_UnsavedDocument))
    {
        // This will remove a frame of lag for selecting another tab on closure.
        // However we don't run it in the case where the 'Unsaved' flag is set, so user gets a chance to fully undo the closure
        tab->WantClose = true;
        if (tab_bar->VisibleTabId == tab->ID)
        {
            tab->LastFrameVisible = -1;
            tab_bar->SelectedTabId = tab_bar->NextSelectedTabId = 0;
        }
    }
    else
    {
        // Actually select before expecting closure attempt (on an UnsavedDocument tab user is expect to e.g. show a popup)
        if (tab_bar->VisibleTabId != tab->ID)
            TabBarQueueFocus(tab_bar, tab);
    }
}

static float SegaUi::TabBarScrollClamp(SegaUiTabBar* tab_bar, float scrolling)
{
    scrolling = ImMin(scrolling, tab_bar->WidthAllTabs - tab_bar->BarRect.GetWidth());
    return ImMax(scrolling, 0.0f);
}

// Note: we may scroll to tab that are not selected! e.g. using keyboard arrow keys
static void SegaUi::TabBarScrollToTab(SegaUiTabBar* tab_bar, SegaUiID tab_id, SegaUiTabBarSection* sections)
{
    SegaUiTabItem* tab = TabBarFindTabByID(tab_bar, tab_id);
    if (tab == NULL)
        return;
    if (tab->Flags & SegaUiTabItemFlags_SectionMask_)
        return;

    SegaUiContext& g = *GSegaUi;
    float margin = g.FontSize * 1.0f; // When to scroll to make Tab N+1 visible always make a bit of N visible to suggest more scrolling area (since we don't have a scrollbar)
    int order = TabBarGetTabOrder(tab_bar, tab);

    // Scrolling happens only in the central section (leading/trailing sections are not scrolling)
    float scrollable_width = TabBarCalcScrollableWidth(tab_bar, sections);

    // We make all tabs positions all relative Sections[0].Width to make code simpler
    float tab_x1 = tab->Offset - sections[0].Width + (order > sections[0].TabCount - 1 ? -margin : 0.0f);
    float tab_x2 = tab->Offset - sections[0].Width + tab->Width + (order + 1 < tab_bar->Tabs.Size - sections[2].TabCount ? margin : 1.0f);
    tab_bar->ScrollingTargetDistToVisibility = 0.0f;
    if (tab_bar->ScrollingTarget > tab_x1 || (tab_x2 - tab_x1 >= scrollable_width))
    {
        // Scroll to the left
        tab_bar->ScrollingTargetDistToVisibility = ImMax(tab_bar->ScrollingAnim - tab_x2, 0.0f);
        tab_bar->ScrollingTarget = tab_x1;
    }
    else if (tab_bar->ScrollingTarget < tab_x2 - scrollable_width)
    {
        // Scroll to the right
        tab_bar->ScrollingTargetDistToVisibility = ImMax((tab_x1 - scrollable_width) - tab_bar->ScrollingAnim, 0.0f);
        tab_bar->ScrollingTarget = tab_x2 - scrollable_width;
    }
}

void SegaUi::TabBarQueueFocus(SegaUiTabBar* tab_bar, SegaUiTabItem* tab)
{
    tab_bar->NextSelectedTabId = tab->ID;
}

void SegaUi::TabBarQueueReorder(SegaUiTabBar* tab_bar, SegaUiTabItem* tab, int offset)
{
    IM_ASSERT(offset != 0);
    IM_ASSERT(tab_bar->ReorderRequestTabId == 0);
    tab_bar->ReorderRequestTabId = tab->ID;
    tab_bar->ReorderRequestOffset = (ImS16)offset;
}

void SegaUi::TabBarQueueReorderFromMousePos(SegaUiTabBar* tab_bar, SegaUiTabItem* src_tab, ImVec2 mouse_pos)
{
    SegaUiContext& g = *GSegaUi;
    IM_ASSERT(tab_bar->ReorderRequestTabId == 0);
    if ((tab_bar->Flags & SegaUiTabBarFlags_Reorderable) == 0)
        return;

    const bool is_central_section = (src_tab->Flags & SegaUiTabItemFlags_SectionMask_) == 0;
    const float bar_offset = tab_bar->BarRect.Min.x - (is_central_section ? tab_bar->ScrollingTarget : 0);

    // Count number of contiguous tabs we are crossing over
    const int dir = (bar_offset + src_tab->Offset) > mouse_pos.x ? -1 : +1;
    const int src_idx = tab_bar->Tabs.index_from_ptr(src_tab);
    int dst_idx = src_idx;
    for (int i = src_idx; i >= 0 && i < tab_bar->Tabs.Size; i += dir)
    {
        // Reordered tabs must share the same section
        const SegaUiTabItem* dst_tab = &tab_bar->Tabs[i];
        if (dst_tab->Flags & SegaUiTabItemFlags_NoReorder)
            break;
        if ((dst_tab->Flags & SegaUiTabItemFlags_SectionMask_) != (src_tab->Flags & SegaUiTabItemFlags_SectionMask_))
            break;
        dst_idx = i;

        // Include spacing after tab, so when mouse cursor is between tabs we would not continue checking further tabs that are not hovered.
        const float x1 = bar_offset + dst_tab->Offset - g.Style.ItemInnerSpacing.x;
        const float x2 = bar_offset + dst_tab->Offset + dst_tab->Width + g.Style.ItemInnerSpacing.x;
        //GetForegroundDrawList()->AddRect(ImVec2(x1, tab_bar->BarRect.Min.y), ImVec2(x2, tab_bar->BarRect.Max.y), IM_COL32(255, 0, 0, 255));
        if ((dir < 0 && mouse_pos.x > x1) || (dir > 0 && mouse_pos.x < x2))
            break;
    }

    if (dst_idx != src_idx)
        TabBarQueueReorder(tab_bar, src_tab, dst_idx - src_idx);
}

bool SegaUi::TabBarProcessReorder(SegaUiTabBar* tab_bar)
{
    SegaUiTabItem* tab1 = TabBarFindTabByID(tab_bar, tab_bar->ReorderRequestTabId);
    if (tab1 == NULL || (tab1->Flags & SegaUiTabItemFlags_NoReorder))
        return false;

    //IM_ASSERT(tab_bar->Flags & SegaUiTabBarFlags_Reorderable); // <- this may happen when using debug tools
    int tab2_order = TabBarGetTabOrder(tab_bar, tab1) + tab_bar->ReorderRequestOffset;
    if (tab2_order < 0 || tab2_order >= tab_bar->Tabs.Size)
        return false;

    // Reordered tabs must share the same section
    // (Note: TabBarQueueReorderFromMousePos() also has a similar test but since we allow direct calls to TabBarQueueReorder() we do it here too)
    SegaUiTabItem* tab2 = &tab_bar->Tabs[tab2_order];
    if (tab2->Flags & SegaUiTabItemFlags_NoReorder)
        return false;
    if ((tab1->Flags & SegaUiTabItemFlags_SectionMask_) != (tab2->Flags & SegaUiTabItemFlags_SectionMask_))
        return false;

    SegaUiTabItem item_tmp = *tab1;
    SegaUiTabItem* src_tab = (tab_bar->ReorderRequestOffset > 0) ? tab1 + 1 : tab2;
    SegaUiTabItem* dst_tab = (tab_bar->ReorderRequestOffset > 0) ? tab1 : tab2 + 1;
    const int move_count = (tab_bar->ReorderRequestOffset > 0) ? tab_bar->ReorderRequestOffset : -tab_bar->ReorderRequestOffset;
    memmove(dst_tab, src_tab, move_count * sizeof(SegaUiTabItem));
    *tab2 = item_tmp;

    if (tab_bar->Flags & SegaUiTabBarFlags_SaveSettings)
        MarkIniSettingsDirty();
    return true;
}

static SegaUiTabItem* SegaUi::TabBarScrollingButtons(SegaUiTabBar* tab_bar)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;

    const ImVec2 arrow_button_size(g.FontSize - 2.0f, g.FontSize + g.Style.FramePadding.y * 2.0f);
    const float scrolling_buttons_width = arrow_button_size.x * 2.0f;

    const ImVec2 backup_cursor_pos = window->DC.CursorPos;
    //window->DrawList->AddRect(ImVec2(tab_bar->BarRect.Max.x - scrolling_buttons_width, tab_bar->BarRect.Min.y), ImVec2(tab_bar->BarRect.Max.x, tab_bar->BarRect.Max.y), IM_COL32(255,0,0,255));

    int select_dir = 0;
    ImVec4 arrow_col = g.Style.Colors[SegaUiCol_Text];
    arrow_col.w *= 0.5f;

    PushStyleColor(SegaUiCol_Text, arrow_col);
    PushStyleColor(SegaUiCol_Button, ImVec4(0, 0, 0, 0));
    const float backup_repeat_delay = g.IO.KeyRepeatDelay;
    const float backup_repeat_rate = g.IO.KeyRepeatRate;
    g.IO.KeyRepeatDelay = 0.250f;
    g.IO.KeyRepeatRate = 0.200f;
    float x = ImMax(tab_bar->BarRect.Min.x, tab_bar->BarRect.Max.x - scrolling_buttons_width);
    window->DC.CursorPos = ImVec2(x, tab_bar->BarRect.Min.y);
    if (ArrowButtonEx("##<", SegaUiDir_Left, arrow_button_size, SegaUiButtonFlags_PressedOnClick | SegaUiButtonFlags_Repeat))
        select_dir = -1;
    window->DC.CursorPos = ImVec2(x + arrow_button_size.x, tab_bar->BarRect.Min.y);
    if (ArrowButtonEx("##>", SegaUiDir_Right, arrow_button_size, SegaUiButtonFlags_PressedOnClick | SegaUiButtonFlags_Repeat))
        select_dir = +1;
    PopStyleColor(2);
    g.IO.KeyRepeatRate = backup_repeat_rate;
    g.IO.KeyRepeatDelay = backup_repeat_delay;

    SegaUiTabItem* tab_to_scroll_to = NULL;
    if (select_dir != 0)
        if (SegaUiTabItem* tab_item = TabBarFindTabByID(tab_bar, tab_bar->SelectedTabId))
        {
            int selected_order = TabBarGetTabOrder(tab_bar, tab_item);
            int target_order = selected_order + select_dir;

            // Skip tab item buttons until another tab item is found or end is reached
            while (tab_to_scroll_to == NULL)
            {
                // If we are at the end of the list, still scroll to make our tab visible
                tab_to_scroll_to = &tab_bar->Tabs[(target_order >= 0 && target_order < tab_bar->Tabs.Size) ? target_order : selected_order];

                // Cross through buttons
                // (even if first/last item is a button, return it so we can update the scroll)
                if (tab_to_scroll_to->Flags & SegaUiTabItemFlags_Button)
                {
                    target_order += select_dir;
                    selected_order += select_dir;
                    tab_to_scroll_to = (target_order < 0 || target_order >= tab_bar->Tabs.Size) ? tab_to_scroll_to : NULL;
                }
            }
        }
    window->DC.CursorPos = backup_cursor_pos;
    tab_bar->BarRect.Max.x -= scrolling_buttons_width + 1.0f;

    return tab_to_scroll_to;
}

static SegaUiTabItem* SegaUi::TabBarTabListPopupButton(SegaUiTabBar* tab_bar)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;

    // We use g.Style.FramePadding.y to match the square ArrowButton size
    const float tab_list_popup_button_width = g.FontSize + g.Style.FramePadding.y;
    const ImVec2 backup_cursor_pos = window->DC.CursorPos;
    window->DC.CursorPos = ImVec2(tab_bar->BarRect.Min.x - g.Style.FramePadding.y, tab_bar->BarRect.Min.y);
    tab_bar->BarRect.Min.x += tab_list_popup_button_width;

    ImVec4 arrow_col = g.Style.Colors[SegaUiCol_Text];
    arrow_col.w *= 0.5f;
    PushStyleColor(SegaUiCol_Text, arrow_col);
    PushStyleColor(SegaUiCol_Button, ImVec4(0, 0, 0, 0));
    bool open = BeginCombo("##v", NULL, SegaUiComboFlags_NoPreview | SegaUiComboFlags_HeightLargest);
    PopStyleColor(2);

    SegaUiTabItem* tab_to_select = NULL;
    if (open)
    {
        for (int tab_n = 0; tab_n < tab_bar->Tabs.Size; tab_n++)
        {
            SegaUiTabItem* tab = &tab_bar->Tabs[tab_n];
            if (tab->Flags & SegaUiTabItemFlags_Button)
                continue;

            const char* tab_name = TabBarGetTabName(tab_bar, tab);
            if (Selectable(tab_name, tab_bar->SelectedTabId == tab->ID))
                tab_to_select = tab;
        }
        EndCombo();
    }

    window->DC.CursorPos = backup_cursor_pos;
    return tab_to_select;
}

//-------------------------------------------------------------------------
// [SECTION] Widgets: BeginTabItem, EndTabItem, etc.
//-------------------------------------------------------------------------
// - BeginTabItem()
// - EndTabItem()
// - TabItemButton()
// - TabItemEx() [Internal]
// - SetTabItemClosed()
// - TabItemCalcSize() [Internal]
// - TabItemBackground() [Internal]
// - TabItemLabelAndCloseButton() [Internal]
//-------------------------------------------------------------------------

bool    SegaUi::BeginTabItem(const char* label, bool* p_open, SegaUiTabItemFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    SegaUiTabBar* tab_bar = g.CurrentTabBar;
    if (tab_bar == NULL)
    {
        IM_ASSERT_USER_ERROR(tab_bar, "Needs to be called between BeginTabBar() and EndTabBar()!");
        return false;
    }
    IM_ASSERT(!(flags & SegaUiTabItemFlags_Button)); // BeginTabItem() Can't be used with button flags, use TabItemButton() instead!

    bool ret = TabItemEx(tab_bar, label, p_open, flags, NULL);
    if (ret && !(flags & SegaUiTabItemFlags_NoPushId))
    {
        SegaUiTabItem* tab = &tab_bar->Tabs[tab_bar->LastTabItemIdx];
        PushOverrideID(tab->ID); // We already hashed 'label' so push into the ID stack directly instead of doing another hash through PushID(label)
    }
    return ret;
}

void    SegaUi::EndTabItem()
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return;

    SegaUiTabBar* tab_bar = g.CurrentTabBar;
    if (tab_bar == NULL)
    {
        IM_ASSERT_USER_ERROR(tab_bar != NULL, "Needs to be called between BeginTabBar() and EndTabBar()!");
        return;
    }
    IM_ASSERT(tab_bar->LastTabItemIdx >= 0);
    SegaUiTabItem* tab = &tab_bar->Tabs[tab_bar->LastTabItemIdx];
    if (!(tab->Flags & SegaUiTabItemFlags_NoPushId))
        PopID();
}

bool    SegaUi::TabItemButton(const char* label, SegaUiTabItemFlags flags)
{
    SegaUiContext& g = *GSegaUi;
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    SegaUiTabBar* tab_bar = g.CurrentTabBar;
    if (tab_bar == NULL)
    {
        IM_ASSERT_USER_ERROR(tab_bar != NULL, "Needs to be called between BeginTabBar() and EndTabBar()!");
        return false;
    }
    return TabItemEx(tab_bar, label, NULL, flags | SegaUiTabItemFlags_Button | SegaUiTabItemFlags_NoReorder, NULL);
}

bool    SegaUi::TabItemEx(SegaUiTabBar* tab_bar, const char* label, bool* p_open, SegaUiTabItemFlags flags, SegaUiWindow* docked_window)
{
    // Layout whole tab bar if not already done
    SegaUiContext& g = *GSegaUi;
    if (tab_bar->WantLayout)
    {
        SegaUiNextItemData backup_next_item_data = g.NextItemData;
        TabBarLayout(tab_bar);
        g.NextItemData = backup_next_item_data;
    }
    SegaUiWindow* window = g.CurrentWindow;
    if (window->SkipItems)
        return false;

    const SegaUiStyle& style = g.Style;
    const SegaUiID id = TabBarCalcTabID(tab_bar, label, docked_window);

    // If the user called us with *p_open == false, we early out and don't render.
    // We make a call to ItemAdd() so that attempts to use a contextual popup menu with an implicit ID won't use an older ID.
    SEGAUI_TEST_ENGINE_ITEM_INFO(id, label, g.LastItemData.StatusFlags);
    if (p_open && !*p_open)
    {
        ItemAdd(ImRect(), id, NULL, SegaUiItemFlags_NoNav);
        return false;
    }

    IM_ASSERT(!p_open || !(flags & SegaUiTabItemFlags_Button));
    IM_ASSERT((flags & (SegaUiTabItemFlags_Leading | SegaUiTabItemFlags_Trailing)) != (SegaUiTabItemFlags_Leading | SegaUiTabItemFlags_Trailing)); // Can't use both Leading and Trailing

    // Store into SegaUiTabItemFlags_NoCloseButton, also honor SegaUiTabItemFlags_NoCloseButton passed by user (although not documented)
    if (flags & SegaUiTabItemFlags_NoCloseButton)
        p_open = NULL;
    else if (p_open == NULL)
        flags |= SegaUiTabItemFlags_NoCloseButton;

    // Acquire tab data
    SegaUiTabItem* tab = TabBarFindTabByID(tab_bar, id);
    bool tab_is_new = false;
    if (tab == NULL)
    {
        tab_bar->Tabs.push_back(SegaUiTabItem());
        tab = &tab_bar->Tabs.back();
        tab->ID = id;
        tab_bar->TabsAddedNew = tab_is_new = true;
    }
    tab_bar->LastTabItemIdx = (ImS16)tab_bar->Tabs.index_from_ptr(tab);

    // Calculate tab contents size
    ImVec2 size = TabItemCalcSize(label, (p_open != NULL) || (flags & SegaUiTabItemFlags_UnsavedDocument));
    tab->RequestedWidth = -1.0f;
    if (g.NextItemData.Flags & SegaUiNextItemDataFlags_HasWidth)
        size.x = tab->RequestedWidth = g.NextItemData.Width;
    if (tab_is_new)
        tab->Width = ImMax(1.0f, size.x);
    tab->ContentWidth = size.x;
    tab->BeginOrder = tab_bar->TabsActiveCount++;

    const bool tab_bar_appearing = (tab_bar->PrevFrameVisible + 1 < g.FrameCount);
    const bool tab_bar_focused = (tab_bar->Flags & SegaUiTabBarFlags_IsFocused) != 0;
    const bool tab_appearing = (tab->LastFrameVisible + 1 < g.FrameCount);
    const bool tab_just_unsaved = (flags & SegaUiTabItemFlags_UnsavedDocument) && !(tab->Flags & SegaUiTabItemFlags_UnsavedDocument);
    const bool is_tab_button = (flags & SegaUiTabItemFlags_Button) != 0;
    tab->LastFrameVisible = g.FrameCount;
    tab->Flags = flags;

    // Append name _WITH_ the zero-terminator
    if (docked_window != NULL)
    {
        IM_ASSERT(docked_window == NULL); // master branch only
    }
    else
    {
        tab->NameOffset = (ImS32)tab_bar->TabsNames.size();
        tab_bar->TabsNames.append(label, label + strlen(label) + 1);
    }

    // Update selected tab
    if (!is_tab_button)
    {
        if (tab_appearing && (tab_bar->Flags & SegaUiTabBarFlags_AutoSelectNewTabs) && tab_bar->NextSelectedTabId == 0)
            if (!tab_bar_appearing || tab_bar->SelectedTabId == 0)
                TabBarQueueFocus(tab_bar, tab); // New tabs gets activated
        if ((flags & SegaUiTabItemFlags_SetSelected) && (tab_bar->SelectedTabId != id)) // _SetSelected can only be passed on explicit tab bar
            TabBarQueueFocus(tab_bar, tab);
    }

    // Lock visibility
    // (Note: tab_contents_visible != tab_selected... because CTRL+TAB operations may preview some tabs without selecting them!)
    bool tab_contents_visible = (tab_bar->VisibleTabId == id);
    if (tab_contents_visible)
        tab_bar->VisibleTabWasSubmitted = true;

    // On the very first frame of a tab bar we let first tab contents be visible to minimize appearing glitches
    if (!tab_contents_visible && tab_bar->SelectedTabId == 0 && tab_bar_appearing)
        if (tab_bar->Tabs.Size == 1 && !(tab_bar->Flags & SegaUiTabBarFlags_AutoSelectNewTabs))
            tab_contents_visible = true;

    // Note that tab_is_new is not necessarily the same as tab_appearing! When a tab bar stops being submitted
    // and then gets submitted again, the tabs will have 'tab_appearing=true' but 'tab_is_new=false'.
    if (tab_appearing && (!tab_bar_appearing || tab_is_new))
    {
        ItemAdd(ImRect(), id, NULL, SegaUiItemFlags_NoNav);
        if (is_tab_button)
            return false;
        return tab_contents_visible;
    }

    if (tab_bar->SelectedTabId == id)
        tab->LastFrameSelected = g.FrameCount;

    // Backup current layout position
    const ImVec2 backup_main_cursor_pos = window->DC.CursorPos;

    // Layout
    const bool is_central_section = (tab->Flags & SegaUiTabItemFlags_SectionMask_) == 0;
    size.x = tab->Width;
    if (is_central_section)
        window->DC.CursorPos = tab_bar->BarRect.Min + ImVec2(IM_FLOOR(tab->Offset - tab_bar->ScrollingAnim), 0.0f);
    else
        window->DC.CursorPos = tab_bar->BarRect.Min + ImVec2(tab->Offset, 0.0f);
    ImVec2 pos = window->DC.CursorPos;
    ImRect bb(pos, pos + size);

    // We don't have CPU clipping primitives to clip the CloseButton (until it becomes a texture), so need to add an extra draw call (temporary in the case of vertical animation)
    const bool want_clip_rect = is_central_section && (bb.Min.x < tab_bar->ScrollingRectMinX || bb.Max.x > tab_bar->ScrollingRectMaxX);
    if (want_clip_rect)
        PushClipRect(ImVec2(ImMax(bb.Min.x, tab_bar->ScrollingRectMinX), bb.Min.y - 1), ImVec2(tab_bar->ScrollingRectMaxX, bb.Max.y), true);

    ImVec2 backup_cursor_max_pos = window->DC.CursorMaxPos;
    ItemSize(bb.GetSize(), style.FramePadding.y);
    window->DC.CursorMaxPos = backup_cursor_max_pos;

    if (!ItemAdd(bb, id))
    {
        if (want_clip_rect)
            PopClipRect();
        window->DC.CursorPos = backup_main_cursor_pos;
        return tab_contents_visible;
    }

    // Click to Select a tab
    SegaUiButtonFlags button_flags = ((is_tab_button ? SegaUiButtonFlags_PressedOnClickRelease : SegaUiButtonFlags_PressedOnClick) | SegaUiButtonFlags_AllowItemOverlap);
    if (g.DragDropActive)
        button_flags |= SegaUiButtonFlags_PressedOnDragDropHold;
    bool hovered, held;
    bool pressed = ButtonBehavior(bb, id, &hovered, &held, button_flags);
    if (pressed && !is_tab_button)
        TabBarQueueFocus(tab_bar, tab);

    // Allow the close button to overlap unless we are dragging (in which case we don't want any overlapping tabs to be hovered)
    if (g.ActiveId != id)
        SetItemAllowOverlap();

    // Drag and drop: re-order tabs
    if (held && !tab_appearing && IsMouseDragging(0))
    {
        if (!g.DragDropActive && (tab_bar->Flags & SegaUiTabBarFlags_Reorderable))
        {
            // While moving a tab it will jump on the other side of the mouse, so we also test for MouseDelta.x
            if (g.IO.MouseDelta.x < 0.0f && g.IO.MousePos.x < bb.Min.x)
            {
                TabBarQueueReorderFromMousePos(tab_bar, tab, g.IO.MousePos);
            }
            else if (g.IO.MouseDelta.x > 0.0f && g.IO.MousePos.x > bb.Max.x)
            {
                TabBarQueueReorderFromMousePos(tab_bar, tab, g.IO.MousePos);
            }
        }
    }

#if 0
    if (hovered && g.HoveredIdNotActiveTimer > TOOLTIP_DELAY && bb.GetWidth() < tab->ContentWidth)
    {
        // Enlarge tab display when hovering
        bb.Max.x = bb.Min.x + IM_FLOOR(ImLerp(bb.GetWidth(), tab->ContentWidth, ImSaturate((g.HoveredIdNotActiveTimer - 0.40f) * 6.0f)));
        display_draw_list = GetForegroundDrawList(window);
        TabItemBackground(display_draw_list, bb, flags, GetColorU32(SegaUiCol_TitleBgActive));
    }
#endif

    // Render tab shape
    ImDrawList* display_draw_list = window->DrawList;
    const ImU32 tab_col = GetColorU32((held || hovered) ? SegaUiCol_TabHovered : tab_contents_visible ? (tab_bar_focused ? SegaUiCol_TabActive : SegaUiCol_TabUnfocusedActive) : (tab_bar_focused ? SegaUiCol_Tab : SegaUiCol_TabUnfocused));
    TabItemBackground(display_draw_list, bb, flags, tab_col);
    RenderNavHighlight(bb, id);

    // Select with right mouse button. This is so the common idiom for context menu automatically highlight the current widget.
    const bool hovered_unblocked = IsItemHovered(SegaUiHoveredFlags_AllowWhenBlockedByPopup);
    if (hovered_unblocked && (IsMouseClicked(1) || IsMouseReleased(1)) && !is_tab_button)
        TabBarQueueFocus(tab_bar, tab);

    if (tab_bar->Flags & SegaUiTabBarFlags_NoCloseWithMiddleMouseButton)
        flags |= SegaUiTabItemFlags_NoCloseWithMiddleMouseButton;

    // Render tab label, process close button
    const SegaUiID close_button_id = p_open ? GetIDWithSeed("#CLOSE", NULL, id) : 0;
    bool just_closed;
    bool text_clipped;
    TabItemLabelAndCloseButton(display_draw_list, bb, tab_just_unsaved ? (flags & ~SegaUiTabItemFlags_UnsavedDocument) : flags, tab_bar->FramePadding, label, id, close_button_id, tab_contents_visible, &just_closed, &text_clipped);
    if (just_closed && p_open != NULL)
    {
        *p_open = false;
        TabBarCloseTab(tab_bar, tab);
    }

    // Restore main window position so user can draw there
    if (want_clip_rect)
        PopClipRect();
    window->DC.CursorPos = backup_main_cursor_pos;

    // Tooltip
    // (Won't work over the close button because ItemOverlap systems messes up with HoveredIdTimer-> seems ok)
    // (We test IsItemHovered() to discard e.g. when another item is active or drag and drop over the tab bar, which g.HoveredId ignores)
    // FIXME: This is a mess.
    // FIXME: We may want disabled tab to still display the tooltip?
    if (text_clipped && g.HoveredId == id && !held)
        if (!(tab_bar->Flags & SegaUiTabBarFlags_NoTooltip) && !(tab->Flags & SegaUiTabItemFlags_NoTooltip))
            if (IsItemHovered(SegaUiHoveredFlags_DelayNormal))
                SetTooltip("%.*s", (int)(FindRenderedTextEnd(label) - label), label);

    IM_ASSERT(!is_tab_button || !(tab_bar->SelectedTabId == tab->ID && is_tab_button)); // TabItemButton should not be selected
    if (is_tab_button)
        return pressed;
    return tab_contents_visible;
}

// [Public] This is call is 100% optional but it allows to remove some one-frame glitches when a tab has been unexpectedly removed.
// To use it to need to call the function SetTabItemClosed() between BeginTabBar() and EndTabBar().
// Tabs closed by the close button will automatically be flagged to avoid this issue.
void    SegaUi::SetTabItemClosed(const char* label)
{
    SegaUiContext& g = *GSegaUi;
    bool is_within_manual_tab_bar = g.CurrentTabBar && !(g.CurrentTabBar->Flags & SegaUiTabBarFlags_DockNode);
    if (is_within_manual_tab_bar)
    {
        SegaUiTabBar* tab_bar = g.CurrentTabBar;
        SegaUiID tab_id = TabBarCalcTabID(tab_bar, label, NULL);
        if (SegaUiTabItem* tab = TabBarFindTabByID(tab_bar, tab_id))
            tab->WantClose = true; // Will be processed by next call to TabBarLayout()
    }
}

ImVec2 SegaUi::TabItemCalcSize(const char* label, bool has_close_button_or_unsaved_marker)
{
    SegaUiContext& g = *GSegaUi;
    ImVec2 label_size = CalcTextSize(label, NULL, true);
    ImVec2 size = ImVec2(label_size.x + g.Style.FramePadding.x, label_size.y + g.Style.FramePadding.y * 2.0f);
    if (has_close_button_or_unsaved_marker)
        size.x += g.Style.FramePadding.x + (g.Style.ItemInnerSpacing.x + g.FontSize); // We use Y intentionally to fit the close button circle.
    else
        size.x += g.Style.FramePadding.x + 1.0f;
    return ImVec2(ImMin(size.x, TabBarCalcMaxTabWidth()), size.y);
}

ImVec2 SegaUi::TabItemCalcSize(SegaUiWindow*)
{
    IM_ASSERT(0); // This function exists to facilitate merge with 'docking' branch.
    return ImVec2(0.0f, 0.0f);
}

void SegaUi::TabItemBackground(ImDrawList* draw_list, const ImRect& bb, SegaUiTabItemFlags flags, ImU32 col)
{
    // While rendering tabs, we trim 1 pixel off the top of our bounding box so they can fit within a regular frame height while looking "detached" from it.
    SegaUiContext& g = *GSegaUi;
    const float width = bb.GetWidth();
    IM_UNUSED(flags);
    IM_ASSERT(width > 0.0f);
    const float rounding = ImMax(0.0f, ImMin((flags & SegaUiTabItemFlags_Button) ? g.Style.FrameRounding : g.Style.TabRounding, width * 0.5f - 1.0f));
    const float y1 = bb.Min.y + 1.0f;
    const float y2 = bb.Max.y - 1.0f;
    draw_list->PathLineTo(ImVec2(bb.Min.x, y2));
    draw_list->PathArcToFast(ImVec2(bb.Min.x + rounding, y1 + rounding), rounding, 6, 9);
    draw_list->PathArcToFast(ImVec2(bb.Max.x - rounding, y1 + rounding), rounding, 9, 12);
    draw_list->PathLineTo(ImVec2(bb.Max.x, y2));
    draw_list->PathFillConvex(col);
    if (g.Style.TabBorderSize > 0.0f)
    {
        draw_list->PathLineTo(ImVec2(bb.Min.x + 0.5f, y2));
        draw_list->PathArcToFast(ImVec2(bb.Min.x + rounding + 0.5f, y1 + rounding + 0.5f), rounding, 6, 9);
        draw_list->PathArcToFast(ImVec2(bb.Max.x - rounding - 0.5f, y1 + rounding + 0.5f), rounding, 9, 12);
        draw_list->PathLineTo(ImVec2(bb.Max.x - 0.5f, y2));
        draw_list->PathStroke(GetColorU32(SegaUiCol_Border), 0, g.Style.TabBorderSize);
    }
}

// Render text label (with custom clipping) + Unsaved Document marker + Close Button logic
// We tend to lock style.FramePadding for a given tab-bar, hence the 'frame_padding' parameter.
void SegaUi::TabItemLabelAndCloseButton(ImDrawList* draw_list, const ImRect& bb, SegaUiTabItemFlags flags, ImVec2 frame_padding, const char* label, SegaUiID tab_id, SegaUiID close_button_id, bool is_contents_visible, bool* out_just_closed, bool* out_text_clipped)
{
    SegaUiContext& g = *GSegaUi;
    ImVec2 label_size = CalcTextSize(label, NULL, true);

    if (out_just_closed)
        *out_just_closed = false;
    if (out_text_clipped)
        *out_text_clipped = false;

    if (bb.GetWidth() <= 1.0f)
        return;

    // In Style V2 we'll have full override of all colors per state (e.g. focused, selected)
    // But right now if you want to alter text color of tabs this is what you need to do.
#if 0
    const float backup_alpha = g.Style.Alpha;
    if (!is_contents_visible)
        g.Style.Alpha *= 0.7f;
#endif

    // Render text label (with clipping + alpha gradient) + unsaved marker
    ImRect text_pixel_clip_bb(bb.Min.x + frame_padding.x, bb.Min.y + frame_padding.y, bb.Max.x - frame_padding.x, bb.Max.y);
    ImRect text_ellipsis_clip_bb = text_pixel_clip_bb;

    // Return clipped state ignoring the close button
    if (out_text_clipped)
    {
        *out_text_clipped = (text_ellipsis_clip_bb.Min.x + label_size.x) > text_pixel_clip_bb.Max.x;
        //draw_list->AddCircle(text_ellipsis_clip_bb.Min, 3.0f, *out_text_clipped ? IM_COL32(255, 0, 0, 255) : IM_COL32(0, 255, 0, 255));
    }

    const float button_sz = g.FontSize;
    const ImVec2 button_pos(ImMax(bb.Min.x, bb.Max.x - frame_padding.x * 2.0f - button_sz), bb.Min.y);

    // Close Button & Unsaved Marker
    // We are relying on a subtle and confusing distinction between 'hovered' and 'g.HoveredId' which happens because we are using SegaUiButtonFlags_AllowOverlapMode + SetItemAllowOverlap()
    //  'hovered' will be true when hovering the Tab but NOT when hovering the close button
    //  'g.HoveredId==id' will be true when hovering the Tab including when hovering the close button
    //  'g.ActiveId==close_button_id' will be true when we are holding on the close button, in which case both hovered booleans are false
    bool close_button_pressed = false;
    bool close_button_visible = false;
    if (close_button_id != 0)
        if (is_contents_visible || bb.GetWidth() >= ImMax(button_sz, g.Style.TabMinWidthForCloseButton))
            if (g.HoveredId == tab_id || g.HoveredId == close_button_id || g.ActiveId == tab_id || g.ActiveId == close_button_id)
                close_button_visible = true;
    bool unsaved_marker_visible = (flags & SegaUiTabItemFlags_UnsavedDocument) != 0 && (button_pos.x + button_sz <= bb.Max.x);

    if (close_button_visible)
    {
        SegaUiLastItemData last_item_backup = g.LastItemData;
        PushStyleVar(SegaUiStyleVar_FramePadding, frame_padding);
        if (CloseButton(close_button_id, button_pos))
            close_button_pressed = true;
        PopStyleVar();
        g.LastItemData = last_item_backup;

        // Close with middle mouse button
        if (!(flags & SegaUiTabItemFlags_NoCloseWithMiddleMouseButton) && IsMouseClicked(2))
            close_button_pressed = true;
    }
    else if (unsaved_marker_visible)
    {
        const ImRect bullet_bb(button_pos, button_pos + ImVec2(button_sz, button_sz) + g.Style.FramePadding * 2.0f);
        RenderBullet(draw_list, bullet_bb.GetCenter(), GetColorU32(SegaUiCol_Text));
    }

    // This is all rather complicated
    // (the main idea is that because the close button only appears on hover, we don't want it to alter the ellipsis position)
    // FIXME: if FramePadding is noticeably large, ellipsis_max_x will be wrong here (e.g. #3497), maybe for consistency that parameter of RenderTextEllipsis() shouldn't exist..
    float ellipsis_max_x = close_button_visible ? text_pixel_clip_bb.Max.x : bb.Max.x - 1.0f;
    if (close_button_visible || unsaved_marker_visible)
    {
        text_pixel_clip_bb.Max.x -= close_button_visible ? (button_sz) : (button_sz * 0.80f);
        text_ellipsis_clip_bb.Max.x -= unsaved_marker_visible ? (button_sz * 0.80f) : 0.0f;
        ellipsis_max_x = text_pixel_clip_bb.Max.x;
    }
    RenderTextEllipsis(draw_list, text_ellipsis_clip_bb.Min, text_ellipsis_clip_bb.Max, text_pixel_clip_bb.Max.x, ellipsis_max_x, label, NULL, &label_size);

#if 0
    if (!is_contents_visible)
        g.Style.Alpha = backup_alpha;
#endif

    if (out_just_closed)
        *out_just_closed = close_button_pressed;
}


#endif // #ifndef SEGAUI_DISABLE
