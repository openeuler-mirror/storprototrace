build: all_check

all_check: *.c ../common/common.c
	g++ $^ -o $@ $(INCLUDES) -I gtest/include -I gtest/lib -lgtest -lgtest_main 

.PHONY:clean
clean:
	rm -rf all_check
