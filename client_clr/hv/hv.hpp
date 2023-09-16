#pragma once

/**
 * @copyright 2018 HeWei, all rights reserved.
 */

// platform
#include "hconfig.hpp"
#include "hexport.hpp"
#include "hplatform.hpp"

// c
#include "hdef.hpp"   // <stddef.hpp"
#include "hatomic.hpp"// <stdatomic.hpp"
#include "herr.hpp"   // <errno.hpp"
#include "htime.hpp"  // <time.hpp"
#include "hmath.hpp"  // <math.hpp"

#include "hbase.hpp"
#include "hversion.hpp"
#include "hsysinfo.hpp"
#include "hproc.hpp"
#include "hthread.hpp"
#include "hmutex.hpp"
#include "hsocket.hpp"

#include "hlog.hpp"
#include "hbuf.hpp"

// cpp
#ifdef __cplusplus
#include "hmap.hpp"       // <map>
#include "hstring.hpp"    // <string>
#include "hfile.hpp"
#include "hpath.hpp"
#include "hdir.hpp"
#include "hurl.hpp"


#endif  // HV_H_
