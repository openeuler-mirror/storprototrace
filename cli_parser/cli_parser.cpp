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
#include <fstream>

using namespace std;
using namespace std::filesystem;

DEFINE_bool(h, false, "show short help message");
DEFINE_bool(once, false, "show event only once");
DEFINE_uint32(cid, 0, "connection id");
DEFINE_uint32(sid, 0, "session id");
DEFINE_string(target, "", "target name");
DEFINE_string(initiatorname, "", "initiator name");
DEFINE_bool(verbose, false, "detailed debugging information");


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

/*
 * validate targetname
 */
bool validate_targetname()
{
	gflags::CommandLineFlagInfo info_target;

	if (gflags::GetCommandLineFlagInfo("target", &info_target) && info_target.is_default)
		return true;

	ostringstream oss;

	oss << "/etc/iscsi/nodes/" << FLAGS_target;

	if (!exists(oss.str())) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	return true;
}

/*
 * validate initiatorname
 */
bool validate_initiatorname()
{
	gflags::CommandLineFlagInfo info;

	if (gflags::GetCommandLineFlagInfo("initiatorname", &info) && info.is_default)
		return true;

	path iscsi_session_prefix = "/sys/class/iscsi_session";
	std::string target_initiatorname = FLAGS_initiatorname;

	if (!exists(iscsi_session_prefix) || !is_directory(iscsi_session_prefix)) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	for (const auto& session : directory_iterator(iscsi_session_prefix)) {
		if (!is_directory(session))
			continue;

		path initiatorname_path = session.path() / "initiatorname";

		if (!exists(initiatorname_path) || !is_regular_file(initiatorname_path))
			continue;

		std::ifstream initiatorname_file(initiatorname_path);
		std::string initiatorname;

		if (std::getline(initiatorname_file, initiatorname))
			if (initiatorname == target_initiatorname)
				return true;
	}

	return false;
}

bool cli_parser(int argc, char** argv) {
	ostringstream oss;
	oss<<"Usage: "<<basename(argv[0])<<" [-h] [-cid CID] [-sid SID] [-target TARGET] [-initiatorname INITIATORNAME] [-verbose VERBOSE]";
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

	if (!validate_targetname()) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	if (!validate_initiatorname()) {
		cout<<gflags::ProgramUsage()<<endl;
		exit(0);
	}

	return true;
}

