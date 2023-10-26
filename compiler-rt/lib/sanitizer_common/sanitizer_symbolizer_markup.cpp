//===-- sanitizer_symbolizer_markup.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between various sanitizers' runtime libraries.
//
// Implementation of offline markup symbolizer.
//===----------------------------------------------------------------------===//

#include "sanitizer_symbolizer_markup.h"

#include "sanitizer_platform.h"
#include "sanitizer_symbolizer.h"
#include "sanitizer_symbolizer_markup_constants.h"

namespace __sanitizer {

bool SymbolizePCMarkup(uptr addr, SymbolizedStack *stack) {
  char buffer[kFormatFunctionMax];
  internal_snprintf(buffer, sizeof(buffer), kFormatFunction, addr);
  stack->info.function = internal_strdup(buffer);
  return true;
}

bool SymbolizeDataMarkup(uptr addr, DataInfo *info) {
  info->Clear();
  info->start = addr;
  return true;
}

const char *DemangleMarkup(const char *name) {
  static char buffer[kFormatDemangleMax];
  internal_snprintf(buffer, sizeof(buffer), kFormatDemangle, name);
  return buffer;
}


void RenderFrameMarkup(InternalScopedString *buffer, int frame_no, uptr address) {
  buffer->AppendF(kFormatFrame, frame_no, address);
}


void RenderDataMarkup(InternalScopedString *buffer, const DataInfo *DI) {
  buffer->AppendF(kFormatData, DI->start);
}

#if !SANITIZER_SYMBOLIZER_FUCHSIA

bool MarkupSymbolizer::SymbolizePC(uptr addr, SymbolizedStack *stack) {
  return SymbolizePCMarkup(addr, stack);
}

bool MarkupSymbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  return SymbolizeDataMarkup(addr, info);
}

// This is used by UBSan for type names, and by ASan for global variable names.
// It's expected to return a static buffer that will be reused on each call.
const char *MarkupSymbolizer::Demangle(const char *name) {
    return DemangleMarkup(name);
}

const char *MarkupStackTracePrinter::StripFunctionName(const char *function) {
  if (!function) {
    return nullptr;
  }

  return function;
}

// We ignore the format argument to __sanitizer_symbolize_global.
void MarkupStackTracePrinter::RenderData(InternalScopedString *buffer,
                                         const char *format, const DataInfo *DI,
                                         const char *strip_path_prefix) {
  return RenderDataMarkup(buffer, DI);
}

bool MarkupStackTracePrinter::RenderNeedsSymbolization(const char *format) {
  return false;
}

// We don't support the stack_trace_format flag at all.
void MarkupStackTracePrinter::RenderFrame(InternalScopedString *buffer,
                                          const char *format, int frame_no,
                                          uptr address, const AddressInfo *info,
                                          bool vs_style,
                                          const char *strip_path_prefix) {
  CHECK(!RenderNeedsSymbolization(format));
  RenderFrameMarkup(buffer, frame_no, address);
}

// Simplier view of a LoadedModule. It only holds information necessary to
// identify unique modules.
struct RenderedModule {
  char *full_name;
  u8 uuid[kModuleUUIDSize];  // BuildId
  uptr base_address;
};

bool ModulesEq(const LoadedModule *module,
               const RenderedModule *renderedModule) {
  return module->base_address() == renderedModule->base_address &&
         internal_memcmp(module->uuid(), renderedModule->uuid,
                         module->uuid_size()) == 0 &&
         internal_strcmp(module->full_name(), renderedModule->full_name) == 0;
}

bool ModuleHasBeenRendered(
    const LoadedModule *module,
    const InternalMmapVectorNoCtor<RenderedModule> *renderedModules) {
  for (auto *it = renderedModules->begin(); it != renderedModules->end();
       ++it) {
    const auto &renderedModule = *it;
    if (ModulesEq(module, &renderedModule)) {
      return true;
    }
  }
  return false;
}

void MarkupStackTracePrinter::RenderModules(InternalScopedString *buffer,
                                            const ListOfModules &modules) {
  // Keeps track of the modules that have been rendered.
  static bool initialized = false;
  static InternalMmapVectorNoCtor<RenderedModule> renderedModules;
  if (!initialized) {
    renderedModules.Initialize(modules.size());
    initialized = true;
  }

  if (!renderedModules.size()) {
    buffer->Append("{{{reset}}}\n");
  }

  for (const auto &module : modules) {
    if (ModuleHasBeenRendered(&module, &renderedModules)) {
      continue;
    }

    buffer->AppendF("{{{module:%d:%s:elf:", renderedModules.size(),
                    module.full_name());
    for (uptr i = 0; i < module.uuid_size(); i++) {
      buffer->AppendF("%02x", module.uuid()[i]);
    }
    buffer->Append("}}}\n");

    for (const auto &range : module.ranges()) {
      buffer->AppendF("{{{mmap:%p:%p:load:%d:r", range.beg,
                      range.end - range.beg, renderedModules.size());
      if (range.writable)
        buffer->Append("w");
      if (range.executable)
        buffer->Append("x");

      // module.base_address == dlpi_addr
      // range.beg == dlpi_addr + p_vaddr
      // relative address == p_vaddr == range.beg - module.base_address
      buffer->AppendF(":%p}}}\n", range.beg - module.base_address());
    }

    renderedModules.push_back({});
    RenderedModule &curModule = renderedModules.back();
    curModule.full_name = internal_strdup(module.full_name());

    // kModuleUUIDSize is the size of curModule.uuid
    CHECK_GE(kModuleUUIDSize, module.uuid_size());
    internal_memcpy(curModule.uuid, module.uuid(), module.uuid_size());

    curModule.base_address = module.base_address();
  }
}

#endif  // SANITIZER_SYMBOLIZER_FUCHSIA

}  // namespace __sanitizer
