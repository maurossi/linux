/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sysrqcrash
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_SYSRQCRASH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SYSRQCRASH_H
#include <trace/hooks/vendor_hooks.h>
/*
 * Following tracepoints are not exported in tracefs and provide a
 * mechanism for vendor modules to hook and extend functionality
 */
DECLARE_HOOK(android_vh_sysrq_crash,
	TP_PROTO(void *data),
	TP_ARGS(data));

#endif /* _TRACE_HOOK_SYSRQCRASH_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
