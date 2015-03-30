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

# Vectors. All commit b'\x00'*32
#
# 01000000019320fd3c8a39f06e9c9eb15f9e9da42545ab6290b0eee41e1adaaa70bf213c2c010000006b483045022100874c836b6ea691139cd536a8a76599cc8d03241f341b82200be043f7c8b863be022039b33944720e9566237c9e55eef5d107ff18991ad59f074b7681682a5eda95ae012102ec7ab7d7acf381bc2fcb393df0abddce876b9ecaa4a7e626f5bb74cd0fd2c609ffffffff010000000000000000226a20000000000000000000000000000000000000000000000000000000000000000000000000 op-ret

# 01000000017f7d117f9faaeb5eb7da4de19190c0b777a38a51fc1ae78a01bd0abbb5c7742f000000006a47304402201b8d6b93845f6f1377b8d4a2b7667b426974496f2c2d056c2bbd74f4d502280c0220276385765faf3c0d561d245c9a3b96ad0b5484b302821e2be69650a8ad72087e012102d0c7ef8458ef3083fe07632bba0a5426de66943237fa13f4bb2f96f44c031692ffffffff01580200000000000017a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc68700000000 p2sh

# 01000000019c2c59a5a7484958ce343924d489b3cb77b7229d461fe5bff55716a1bd6062c9000000006a473044022077512714e09d825d46bd3fb4c6fbd17d040d8068549fdc0320ac6cb08b9e047d02203d36a506f5c39fa98c9efa7c3fde253adeb742e221cf01b3caba1320cf591fdb012102bd46cb2abe37a67200c70452ffe5752f20367705283e091e8e9d14c0207c2605ffffffff0158020000000000001976a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688ac00000000 p2pkh

class Test_FakeSingleUseSeal(unittest.TestCase):
    """Fake seals"""
    def test_verify_hash(self):
        fake_seal = FakeSingleUseSeal(committed_hash=b'\x00'*32)
        fake_witness = FakeSealWitness(seal=fake_seal)

        self.assertIs(fake_witness.seal, fake_seal)

        fake_witness.verify_hash(b'\x00'*32)

        # FIXME: invalid witness test

class Test_SingleUseSeal(unittest.TestCase):
    def test_valid_witness(self):
        seal_outpoint = COutPoint(lx('14180092832c9e49f36e37c2cfa6695a6670cc66dcba42266245e11c8f9de4cf'), 0)
        btc_sus = BitcoinSingleUseSeal(outpoint=seal_outpoint,nonce=b'')

        witness_tx = CTransaction([CTxIn(seal_outpoint)], [CTxOut(0, CScript([OP_RETURN, b'\x00'*32]))])

        txproof = TxProof(tx=witness_tx)
        txinproof = TxInProof(txproof=txproof, i=0)
        txoutproof = TxOutProof(txproof=txproof, i=0)

        btc_sus_witness = BitcoinSealWitness(seal=btc_sus, txinproof=txinproof, txoutproof=txoutproof)

        btc_sus_witness.verify_hash(b'\x00'*32)

    # FIXME: need tests for invalid witnesses
