#ifndef _EVHTTPINT_H
#define _EVHTTPINT_H

#define _GNU_SOURCE
#define EV_MULTIPLICITY	1

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <netdb.h>
#include <math.h>
#include <obstack.h>
#include <signal.h>
#include "ev.h"
#include "fmtshim.h"
#include "dlist.h"
#include "http_headers.h"
#include "mtag.h"

#endif
