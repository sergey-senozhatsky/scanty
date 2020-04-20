#!/bin/sh

# SPDX-License-Identifier: GPL-2.0-only

CXX=gcc
INCL=-I./t/

function run_test
{
	local NUM=$1

	echo "-==--==--<<>>--==--==- test${NUM} -==--==--<<>>--==--==-"
	$CXX ${INCL} -fplugin=./plugin/.libs/libscanty.so -c t/test${NUM}.c -o /dev/null
}

function test_all
{
	for n in {1..12}; do
		run_test $n
	done
}

if [ "z$1" == "z" ]; then
	test_all
else
	run_test $1
fi
