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
	char program[] = "./storprototrace_test";
	char *argv[] = {program};

	EXPECT_TRUE(cli_parser(1, argv));
}

TEST(storprototrace, validate_interval)
{
	gflags::FlagSaver flag_saver;

	FLAGS_interval = 0;
	EXPECT_FALSE(validate_interval());

	FLAGS_interval = 2;
	EXPECT_TRUE(validate_interval());
}

TEST(storprototrace, validate_lun)
{
	gflags::FlagSaver flag_saver;

	gflags::SetCommandLineOption("lun", "invalid");
	EXPECT_FALSE(validate_lun());

	gflags::SetCommandLineOption("lun", "000000000000000g");
	EXPECT_FALSE(validate_lun());

	gflags::SetCommandLineOption("lun", "0000000000000000");
	EXPECT_TRUE(validate_lun());
}

TEST(storprototrace, validate_targetname)
{
	gflags::FlagSaver flag_saver;

	gflags::SetCommandLineOption("target", "__storprototrace_missing_target__");
	EXPECT_FALSE(validate_targetname());
}

TEST(storprototrace, validate_initiatorname)
{
	gflags::FlagSaver flag_saver;

	gflags::SetCommandLineOption("initiatorname",
	                             "__storprototrace_missing_initiator__");
	EXPECT_FALSE(validate_initiatorname());
}

int main(int argc, char *argv[])
{
	::testing::InitGoogleTest(&argc, argv);
	return RUN_ALL_TESTS();
}
