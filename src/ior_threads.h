/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef IOR_THREADS_H
#define IOR_THREADS_H

#include "ior_threads_ring.h"
#include "ior_threads_event.h"
#include "ior_threads_pool.h"

/* Default CQ size multiplier if not specified */
#define IOR_THREADS_CQ_MULTIPLIER 2

/* Default minimum number of entries */
#define IOR_THREADS_MIN_ENTRIES 32

#endif /* IOR_THREADS_BACKEND_H */
