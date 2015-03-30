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
    HASHTAG = HashTag('73777384-88f0-40cc-a836-443cc6db3589')
    KEY_SERIALIZER = UInt64
    VALUE_SERIALIZER = UInt64

    SEAL_CLASS = BitcoinSingleUseSeal
    WITNESS_CLASS = BitcoinSealWitness

    @staticmethod
    def key2prefix(key):
        return Bits.from_bytes(key.to_bytes(4, 'big'))

def make_btc_seal(outpoint_hash=None, nonce=b''):
    if outpoint_hash is None:
        outpoint_hash = os.urandom(32)
    return BitcoinSingleUseSeal(outpoint=COutPoint(outpoint_hash,0), nonce=nonce)

def make_btc_witness(seal, hash):
    tx = CTransaction([CTxIn(seal.outpoint)], [CTxOut(0, CScript([OP_RETURN, hash]))])
    txproof = TxProof(tx=tx)
    txinproof = TxInProof(i=0, txproof=TxProof(tx=tx))
    txoutproof = TxOutProof(i=0, txproof=TxProof(tx=tx))
    return BitcoinSealWitness(seal=seal, txinproof=txinproof, txoutproof=txoutproof)


class Test_GuMap(unittest.TestCase):
    def test_UnusedPrefix(self):
        """UnusedPrefix behavior"""
        unused_seal = make_btc_seal()
        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=unused_seal)

        self.assertIs(unused_prefix.seal, unused_seal)

    def test_LeafPrefix_from_unused_prefix(self):
        """LeafPrefix.from_unused_prefix()"""
        unused_seal = make_btc_seal()
        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=unused_seal)

        leaf_prefix = IntGuMap.LeafPrefix.from_unused_prefix(unused_prefix,
                                                             0, 0,
                                                             make_btc_witness)

        leaf_prefix.verify()

    def test_LeafPrefix_from_unused_prefix(self):
        """LeafPrefix.from_unused_prefix()"""
        left_unused_prefix  = IntGuMap.UnusedPrefix(prefix=Bits([0]), seal=make_btc_seal())
        right_unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits([0]), seal=make_btc_seal())

        unused_prefix = IntGuMap.UnusedPrefix(prefix=Bits(), seal=make_btc_seal())

        inner_prefix = IntGuMap.InnerPrefix.from_unused_prefix(unused_prefix,
                                                               left_unused_prefix,
                                                               right_unused_prefix,
                                                               make_btc_witness)

        inner_prefix.verify()

    def test_fakeseal_trick(self):
        """GuMap's using fake seals"""
        up0 = IntGuMap.UnusedPrefix(prefix=Bits([0]), seal=make_btc_seal())
        up1 = IntGuMap.UnusedPrefix(prefix=Bits([1]), seal=make_btc_seal())

        ip0 = IntGuMap.InnerPrefix.from_children(up0, up1)
        ip0.verify()

        # ip0 itself has a *fake* seal, while it's left and right children have
        # both real seals.

        # Now turn the left child into a leaf node and recreate.
        leaf0 = IntGuMap.LeafPrefix.from_unused_prefix(up0, 0, 0, make_btc_witness)

        ip1 = IntGuMap.InnerPrefix(prefix=ip0.prefix, witness=ip0.witness, left=leaf0, right=ip0.right)
        ip1.verify()

        # Crux of the matter: the seals are the same, but the contents are
        # different! Yet we didn't need a third seal on the ip0 level.
        self.assertEqual(ip0.seal, ip1.seal)
        self.assertNotEqual(ip0, ip1)
