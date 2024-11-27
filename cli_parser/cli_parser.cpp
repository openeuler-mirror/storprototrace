/*
 * Copyright (c) KylinSoft Co., Ltd. 2024-2025.All rights reserved.
 * storprototrace is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *         http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "cli_parser.h"
#include <sstream>
#include <iostream>
#include <libgen.h>

using namespace std;

DEFINE_bool(h, false, "show short help message");
DEFINE_int32(cid, 0, "client id");
DEFINE_int32(sid, 0, "session id");
DEFINE_string(target, "", "target name");
DEFINE_string(initatorname, "", "initator name");
DEFINE_int32(verbose, 0, "detailed debugging information");

bool cli_parser(int argc, char** argv) {
	ostringstream oss;
	oss<<"Usage: "<<basename(argv[0])<<" [-h] [-c CID] [-s SID] [-t TARGET] [-i INITATORNAME] [-v VERBOSE]";
	gflags::SetUsageMessage(oss.str());
	gflags::SetVersionString("version: 1.0-1");
	gflags::ParseCommandLineFlags(&argc, &argv, true);
	if(FLAGS_h) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}
	return true;
}

