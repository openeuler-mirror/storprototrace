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

#include <sys/stat.h>
#include <gtest/gtest.h>
#include "common.h"
#include "cli_parser.h"
#include <stdio.h>
#include <string.h>
#include <string>
using std::string;

TEST(storprototrace, cli_parser)
{
	const char * const_argv[]={"./storprototrace_test", "-cid", "123", "-sid=456", 
		"--target=test_target", "--initiatorname", "test_initiatorname"};
	char buf[7][32];
	char *argv[7];
	for(int i=0;i<7;++i){
		memcpy(buf[i], const_argv[i], strlen(const_argv[i]) + 1);
		argv[i]=buf[i];
	}

	EXPECT_EQ(cli_parser(7, (char**)argv), true);
	EXPECT_EQ(FLAGS_cid, 123);
	EXPECT_EQ(FLAGS_sid, 456);
	EXPECT_EQ(string(FLAGS_target), string("test_target"));
	EXPECT_EQ(string(FLAGS_initiatorname), string("test_initiatorname"));
}

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
