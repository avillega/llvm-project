//===-- sanitizer_symbolizer_markup.h -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between various sanitizers' runtime libraries.
//
// Definitions of the offline markup symbolizer.
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_SYMBOLIZER_MARKUP_H
#define SANITIZER_SYMBOLIZER_MARKUP_H

#include "sanitizer_common.h"
#include "sanitizer_stacktrace_printer.h"
#include "sanitizer_symbolizer.h"
#include "sanitizer_symbolizer_internal.h"

namespace __sanitizer {

bool SymbolizePCMarkup(uptr addr, SymbolizedStack *stack);
bool SymbolizeDataMarkup(uptr addr, DataInfo *info);
const char *DemangleMarkup(const char *name);

void RenderFrameMarkup(InternalScopedString *buffer, int frame_no,
                       uptr address);

void RenderDataMarkup(InternalScopedString *buffer, const DataInfo *DI);


// This generic support for offline symbolizing is based on the
// Fuchsia port.  We don't do any actual symbolization per se.
// Instead, we emit text containing raw addresses and raw linkage
// symbol names, embedded in Fuchsia's symbolization markup format.
// Fuchsia's logging infrastructure emits enough information about
// process memory layout that a post-processing filter can do the
// symbolization and pretty-print the markup.  See the spec at:
// https://fuchsia.googlesource.com/zircon/+/master/docs/symbolizer_markup.md

class MarkupSymbolizer final : public SymbolizerTool {
 public:
  // This is used in some places for suppression checking, which we
  // don't really support for Fuchsia.  It's also used in UBSan to
  // identify a PC location to a function name, so we always fill in
  // the function member with a string containing markup around the PC
  // value.
  // TODO(mcgrathr): Under SANITIZER_GO, it's currently used by TSan
  // to render stack frames, but that should be changed to use
  // RenderStackFrame.
  bool SymbolizePC(uptr addr, SymbolizedStack *stack) override;

  // Always claim we succeeded, so that RenderDataInfo will be called.
  bool SymbolizeData(uptr addr, DataInfo *info) override;

  // May return NULL if demangling failed.
  // This is used by UBSan for type names, and by ASan for global variable
  // names. It's expected to return a static buffer that will be reused on each
  // call.
  const char *Demangle(const char *name) override;
};

class MarkupStackTracePrinter : public StackTracePrinter {
 public:
  const char *StripFunctionName(const char *function) override;

  void RenderFrame(InternalScopedString *buffer, const char *format,
                   int frame_no, uptr address, const AddressInfo *info,
                   bool vs_style, const char *strip_path_prefix = "") override;

  bool RenderNeedsSymbolization(const char *format) override;

  void RenderData(InternalScopedString *buffer, const char *format,
                  const DataInfo *DI,
                  const char *strip_path_prefix = "") override;

  // Render the modules that have not been Rendered since the last call.
  void RenderModules(InternalScopedString *buffer,
                     const ListOfModules &modules);

  // This is not used when emitting sanitizer_markup since the context for
  // the source location is encoded in the modules and backtraces elements.
  void RenderSourceLocation(InternalScopedString *, const char *, int, int,
                            bool, const char *) override {}

  // This is not used when emitting sanitizer_markup since the module is emitted
  // ahead of time.
  void RenderModuleLocation(InternalScopedString *, const char *, uptr,
                            ModuleArch, const char *) override {}

 protected:
  ~MarkupStackTracePrinter() {}
};

}// namespace __sanitizer

#endif  // SANITIZER_SYMBOLIZER_MARKUP_H
