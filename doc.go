// Copyright (c) 2021, 2022 Mark Delany. All rights reserved. Use of this source code is
// governed by a BSD-style license that can be found in the LICENSE file.

// This file exists so that "go doc github.com/markdingo/autoreverse" displays something
// useful.

/*

Package autoreverse is a specialized authoritative DNS server whose goal is to make it as
easy as possible to auto-answer reverse queries without ever requiring reverse zone files.
autoreverse synthesizes reverse answers and automatically derives PTR answers from
specified forward zones.

autoreverse is designed to run on residential gateway routers and servers behind NATs
which acquire ISP-assigned addresses via DHCP or SLAAC, but it also runs on publicly
accessible servers with static network configurations.

Project site: https://github.com/markdingo/autoreverse

*/
package autoreverse
