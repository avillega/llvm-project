//===-- sanitizer_symbolizer_fuchsia.cpp
//-----------------------------------===//
//
// Part of the LLVM Proect, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Implementation of offline markup symbolizer for fuchsia.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_SYMBOLIZER_FUCHSIA

#  include <limits.h>
#  include <unwind.h>

#  include "sanitizer_stacktrace.h"
#  include "sanitizer_stacktrace_printer.h"
#  include "sanitizer_symbolizer.h"
#  include "sanitizer_symbolizer_markup.h"

namespace __sanitizer {

class FuchsiaStackTracePrinter : public StackTracePrinter {
 public:
  const char *StripFunctionName(const char *function) override {
    if (!function) {
      return nullptr;
    }

    return function;
  }

  void RenderFrame(InternalScopedString *buffer, const char *format,
                   int frame_no, uptr address, const AddressInfo *info,
                   bool vs_style, const char *strip_path_prefix = "") override {
    RenderFrameMarkup(buffer, frame_no, address);
  }

  bool RenderNeedsSymbolization(const char *format) override { return false; }

  void RenderData(InternalScopedString *buffer, const char *format,
                  const DataInfo *DI,
                  const char *strip_path_prefix = "") override {
    RenderDataMarkup(buffer, DI);
  }

  // This is not used when emitting sanitizer_markup since the context for
  // the source location is encoded in the modules and backtraces elements.
  void RenderSourceLocation(InternalScopedString *, const char *, int, int,
                            bool, const char *) override {}

  // This is not used when emitting sanitizer_markup since the module is emitted
  // ahead of time.
  void RenderModuleLocation(InternalScopedString *, const char *, uptr,
                            ModuleArch, const char *) override {}

 protected:
  ~FuchsiaStackTracePrinter() {}
};

StackTracePrinter *StackTracePrinter::GetOrInit() {
  static StackTracePrinter *stacktrace_printer;
  static StaticSpinMutex stacktrace_printer_init_mu;

  SpinMutexLock l(&stacktrace_printer_init_mu);
  if (stacktrace_printer)
    return stacktrace_printer;

  stacktrace_printer =
      new (GetGlobalLowLevelAllocator()) FuchsiaStackTracePrinter();

  CHECK(stacktrace_printer);
  return stacktrace_printer;
}

const char *Symbolizer::Demangle(const char *name) {
  return DemangleMarkup(name);
}

// This is used mostly for suppression matching.  Making it work
// would enable "interceptor_via_lib" suppressions.  It's also used
// once in UBSan to say "in module ..." in a message that also
// includes an address in the module, so post-processing can already
// pretty-print that so as to indicate the module.
bool Symbolizer::GetModuleNameAndOffsetForPC(uptr pc, const char **module_name,
                                             uptr *module_address) {
  return false;
}

// This is mainly used by hwasan for online symbolization. This isn't needed
// since hwasan can always ust dump stack frames for offline symbolization.
bool Symbolizer::SymbolizeFrame(uptr addr, FrameInfo *info) { return false; }

SymbolizedStack *Symbolizer::SymbolizePC(uptr addr) {
  SymbolizedStack *s = SymbolizedStack::New(addr);
  SymbolizePCMarkup(addr, s);
  return s;
}

bool Symbolizer::SymbolizeData(uptr addr, DataInfo *info) {
  return SymbolizeDataMarkup(addr, info);
}

Symbolizer *Symbolizer::PlatformInit() {
  return new (symbolizer_allocator_) Symbolizer({});
}

void Symbolizer::LateInitialize() { Symbolizer::GetOrInit(); }

void StartReportDeadlySignal() {}
void ReportDeadlySignal(const SignalContext &sig, u32 tid,
                        UnwindSignalStackCallbackType unwind,
                        const void *unwind_context) {}

#  if SANITIZER_CAN_SLOW_UNWIND
struct UnwindTraceArg {
  BufferedStackTrace *stack;
  u32 max_depth;
};

_Unwind_Reason_Code Unwind_Trace(struct _Unwind_Context *ctx, void *param) {
  UnwindTraceArg *arg = static_cast<UnwindTraceArg *>(param);
  CHECK_LT(arg->stack->size, arg->max_depth);
  uptr pc = _Unwind_GetIP(ctx);
  if (pc < PAGE_SIZE)
    return _URC_NORMAL_STOP;
  arg->stack->trace_buffer[arg->stack->size++] = pc;
  return (arg->stack->size == arg->max_depth ? _URC_NORMAL_STOP
                                             : _URC_NO_REASON);
}

void BufferedStackTrace::UnwindSlow(uptr pc, u32 max_depth) {
  CHECK_GE(max_depth, 2);
  size = 0;
  UnwindTraceArg arg = {this, Min(max_depth + 1, kStackTraceMax)};
  _Unwind_Backtrace(Unwind_Trace, &arg);
  CHECK_GT(size, 0);
  // We need to pop a few frames so that pc is on top.
  uptr to_pop = LocatePcInTrace(pc);
  // trace_buffer[0] belongs to the current function so we always pop it,
  // unless there is only 1 frame in the stack trace (1 frame is always better
  // than 0!).
  PopStackFrames(Min(to_pop, static_cast<uptr>(1)));
  trace_buffer[0] = pc;
}

void BufferedStackTrace::UnwindSlow(uptr pc, void *context, u32 max_depth) {
  CHECK(context);
  CHECK_GE(max_depth, 2);
  UNREACHABLE("signal context doesn't exist");
}
#  endif  // SANITIZER_CAN_SLOW_UNWIND

}  // namespace __sanitizer

#endif  // SANITIZER_SYMBOLIZER_FUCHSIA
