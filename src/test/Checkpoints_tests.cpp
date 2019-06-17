// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Unit tests for block-chain checkpoints
//

#include "checkpoints.h"

#include "uint256.h"

#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_AUTO_TEST_SUITE(Checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p0 = uint256("0x00000fcfe113ef8d295c0298e53008d49313e524a0e3932c11ef5914670fe7d6");
    
    BOOST_CHECK(Checkpoints::CheckBlock(0, p0));
    
}

BOOST_AUTO_TEST_SUITE_END()
