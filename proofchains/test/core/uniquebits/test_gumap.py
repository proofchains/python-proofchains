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

import os
import unittest

from bitcoin.core import *
from bitcoin.core.script import *

from proofchains.core.uniquebits.singleuseseal import *
from proofchains.core.uniquebits.gumap import *
from proofchains.core.bitcoin import *

from proofmarshal.bits import *
from proofmarshal.serialize import UInt64

@make_GuMap_subclass
class IntGuMap(GuMap):
    __slots__ = []
    HASH_HMAC_KEY = b'\x00'*16
    KEY_SERIALIZER = UInt64
    VALUE_SERIALIZER = UInt64

    SEAL_CLASS = BitcoinSingleUseSeal
    WITNESS_CLASS = BitcoinSealWitness

    @staticmethod
    def key2prefix(key):
        return Bits.from_bytes(key.to_bytes(4, 'big'))

def make_fake_seal(outpoint_hash=None):
    if outpoint_hash is None:
        outpoint_hash = os.urandom(32)
    return BitcoinSingleUseSeal(outpoint=COutPoint(outpoint_hash,0))

def make_fake_witness(seal, hash):
    tx = CTransaction([CTxIn(seal.outpoint)], [CTxOut(0, CScript([OP_RETURN, hash]))])
    txproof = TxProof(tx=tx)
    txinproof = TxInProof(i=0, txproof=TxProof(tx=tx))
    txoutproof = TxOutProof(i=0, txproof=TxProof(tx=tx))
    return BitcoinSealWitness(seal=seal, txinproof=txinproof, txoutproof=txoutproof)


class Test_GuMap(unittest.TestCase):
    def test_UnusedPrefix(self):
        """UnusedPrefix behavior"""
        unused_seal = make_fake_seal()
        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=unused_seal)

        self.assertIs(unused_prefix.seal, unused_seal)

    def test_LeafPrefix_from_unused_prefix(self):
        """LeafPrefix.from_unused_prefix()"""
        unused_seal = make_fake_seal()
        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=unused_seal)

        leaf_prefix = IntGuMap.LeafPrefix.from_unused_prefix(unused_prefix,
                                                             0, 0,
                                                             make_fake_witness)

        leaf_prefix.verify()

    def test_LeafPrefix_from_unused_prefix(self):
        """LeafPrefix.from_unused_prefix()"""
        left_unused_prefix  = IntGuMap.UnusedPrefix(prefix=Bits([0]), seal=make_fake_seal())
        right_unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits([0]), seal=make_fake_seal())

        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=make_fake_seal())

        inner_prefix = IntGuMap.InnerPrefix.from_unused_prefix(unused_prefix,
                                                               left_unused_prefix,
                                                               right_unused_prefix,
                                                               make_fake_witness)

        inner_prefix.verify()
