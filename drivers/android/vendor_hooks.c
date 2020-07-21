// SPDX-License-Identifier: GPL-2.0-only
/* vendor_hook.c
 *
 * Android Vendor Hook Support
 *
 * Copyright 2020 Google LLC
 */

#define CREATE_TRACE_POINTS
#include <trace/hooks/vendor_hooks.h>
#include <trace/hooks/fpsimd.h>
#include <trace/hooks/rwsem.h>
#include <trace/hooks/mpam.h>
#include <trace/hooks/debug.h>

/*
 * Export tracepoints that act as a bare tracehook (ie: have no trace event
 * associated with them) to allow external modules to probe them.
 */
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_is_fpsimd_save);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_rwsem_init);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_rwsem_wake);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_rwsem_write_finished);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_alter_rwsem_list_add);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_mpam_set);
EXPORT_TRACEPOINT_SYMBOL_GPL(android_vh_ipi_stop);
