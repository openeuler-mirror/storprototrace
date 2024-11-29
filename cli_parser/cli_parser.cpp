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
#include <filesystem>

using namespace std;
using namespace std::filesystem;

DEFINE_bool(h, false, "show short help message");
DEFINE_bool(once, false, "show event only once");
DEFINE_uint32(cid, 0, "connection id");
DEFINE_uint32(sid, 0, "session id");
DEFINE_string(target, "", "target name");
DEFINE_string(initatorname, "", "initator name");
DEFINE_int32(verbose, 0, "detailed debugging information");

/*
 * validate sid/cid
 */
bool validate_sid_cid()
{
	gflags::CommandLineFlagInfo info_sid;
	gflags::CommandLineFlagInfo info_cid;
	bool has_sid = false;
	if (gflags::GetCommandLineFlagInfo("sid", &info_sid) && !info_sid.is_default) {
		has_sid = true;
		ostringstream oss;
		oss <<"/sys/class/iscsi_session/session"<<FLAGS_sid;
	        if (!is_directory(oss.str())) {
			cout<<"can not find this session"<<endl;
			return false;
	        }
	}

	if (GetCommandLineFlagInfo("cid", &info_cid) && !info_cid.is_default) {
		if(!has_sid) {
                        cout<<"need sid!"<<endl;
			return false;
		}
                ostringstream oss;
		oss << "/sys/class/iscsi_connection/connection" << FLAGS_sid << ":" << FLAGS_cid;
                if (!is_directory(oss.str())) {
                        cout<<"can not find this connection"<<endl;
			return false;
                }
	}

	return true;
}

bool cli_parser(int argc, char** argv) {
	ostringstream oss;
	oss<<"Usage: "<<basename(argv[0])<<" [-h] [-cid CID] [-sid SID] [-target TARGET] [-initatorname INITATORNAME] [-verbose VERBOSE]";
	oss<<" [-once]";
	gflags::SetUsageMessage(oss.str());
	gflags::SetVersionString("version: 1.0-1");
	gflags::ParseCommandLineFlags(&argc, &argv, true);
	if(FLAGS_h) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	if (!validate_sid_cid()) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	return true;
}

