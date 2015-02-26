# Copyright (C) 2015 Peter Todd <pete@petertodd.org>
#
# This file is part of python-proofchains.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-proofchains, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import unittest

from bitcoin.core import *
from bitcoin.core.script import *

from proofchains.core.uniquebits.singleuseseal import *
from proofchains.core.bitcoin import *

class Test_SingleUseSeal(unittest.TestCase):
    def test_valid_witness(self):
        seal_outpoint = COutPoint(lx('14180092832c9e49f36e37c2cfa6695a6670cc66dcba42266245e11c8f9de4cf'), 0)
        btc_sus = BitcoinSingleUseSeal(outpoint=seal_outpoint)

        witness_tx = CTransaction([CTxIn(seal_outpoint)], [CTxOut(0, CScript([OP_RETURN, b'\x00'*32]))])

        btc_sus_witness = BitcoinSealWitness(seal=btc_sus,
                                             txin_idx=0, txout_idx=0,
                                             txproof=TxProof(tx=witness_tx))

        btc_sus_witness.verify_hash(b'\x00'*32)

    # FIXME: need tests for invalid witnesses
