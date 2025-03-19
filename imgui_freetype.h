// dear imgui: FreeType font builder (used as a replacement for the stb_truetype builder)
// (headers)

#pragma once

#include "imgui.h"      // SEGAUI_API

// Forward declarations
struct ImFontAtlas;
struct ImFontBuilderIO;

// Hinting greatly impacts visuals (and glyph sizes).
// - By default, hinting is enabled and the font's native hinter is preferred over the auto-hinter.
// - When disabled, FreeType generates blurrier glyphs, more or less matches the stb_truetype.h
// - The Default hinting mode usually looks good, but may distort glyphs in an unusual way.
// - The Light hinting mode generates fuzzier glyphs but better matches Microsoft's rasterizer.
// You can set those flags globaly in ImFontAtlas::FontBuilderFlags
// You can set those flags on a per font basis in ImFontConfig::FontBuilderFlags
enum SegaUiFreeTypeBuilderFlags
{
    SegaUiFreeTypeBuilderFlags_NoHinting = 1 << 0,   // Disable hinting. This generally generates 'blurrier' bitmap glyphs when the glyph are rendered in any of the anti-aliased modes.
    SegaUiFreeTypeBuilderFlags_NoAutoHint = 1 << 1,   // Disable auto-hinter.
    SegaUiFreeTypeBuilderFlags_ForceAutoHint = 1 << 2,   // Indicates that the auto-hinter is preferred over the font's native hinter.
    SegaUiFreeTypeBuilderFlags_LightHinting = 1 << 3,   // A lighter hinting algorithm for gray-level modes. Many generated glyphs are fuzzier but better resemble their original shape. This is achieved by snapping glyphs to the pixel grid only vertically (Y-axis), as is done by Microsoft's ClearType and Adobe's proprietary font renderer. This preserves inter-glyph spacing in horizontal text.
    SegaUiFreeTypeBuilderFlags_MonoHinting = 1 << 4,   // Strong hinting algorithm that should only be used for monochrome output.
    SegaUiFreeTypeBuilderFlags_Bold = 1 << 5,   // Styling: Should we artificially embolden the font?
    SegaUiFreeTypeBuilderFlags_Oblique = 1 << 6,   // Styling: Should we slant the font, emulating italic style?
    SegaUiFreeTypeBuilderFlags_Monochrome = 1 << 7,   // Disable anti-aliasing. Combine this with MonoHinting for best results!
    SegaUiFreeTypeBuilderFlags_LoadColor = 1 << 8,   // Enable FreeType color-layered glyphs
    SegaUiFreeTypeBuilderFlags_Bitmap = 1 << 9    // Enable FreeType bitmap glyphs
};

namespace SegaUiFreeType
{
    // This is automatically assigned when using '#define SEGAUI_ENABLE_FREETYPE'.
    // If you need to dynamically select between multiple builders:
    // - you can manually assign this builder with 'atlas->FontBuilderIO = SegaUiFreeType::GetBuilderForFreeType()'
    // - prefer deep-copying this into your own ImFontBuilderIO instance if you use hot-reloading that messes up static data.
    SEGAUI_API const ImFontBuilderIO* GetBuilderForFreeType();

    // Override allocators. By default SegaUiFreeType will use IM_ALLOC()/IM_FREE()
    // However, as FreeType does lots of allocations we provide a way for the user to redirect it to a separate memory heap if desired.
    SEGAUI_API void                      SetAllocatorFunctions(void* (*alloc_func)(size_t sz, void* user_data), void (*free_func)(void* ptr, void* user_data), void* user_data = NULL);

    // Obsolete names (will be removed soon)
    // Prefer using '#define SEGAUI_ENABLE_FREETYPE'
#ifndef SEGAUI_DISABLE_OBSOLETE_FUNCTIONS
    static inline bool BuildFontAtlas(ImFontAtlas* atlas, unsigned int flags = 0) { atlas->FontBuilderIO = GetBuilderForFreeType(); atlas->FontBuilderFlags = flags; return atlas->Build(); }
#endif
}