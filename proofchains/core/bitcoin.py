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

"""Bitcoin-specific proofs"""

import proofmarshal.proof
import proofmarshal.serialize
import bitcoin.core

class CTransactionSerializer(proofmarshal.serialize.Serializer):
    @classmethod
    def check_instance(cls, tx):
        if not isinstance(tx, bitcoin.core.CTransaction):
            raise proofmarshal.serialize.SerializerTypeError('Expected CTransaction; got %r' % value.__class__)

    @classmethod
    def ctx_serialize(cls, tx, ctx):
        serialized_tx = tx.serialize()

        # FIXME: should have a write variable-length bytes...
        ctx.write_varuint(len(serialized_tx))
        ctx.write_bytes(serialized_tx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        l = ctx.read_varuint()
        serialized_tx = ctx.read_bytes(l)
        tx = bitcoin.core.CTransaction.deserialize(tx)
        return tx

class COutPointSerializer(proofmarshal.serialize.Serializer):
    @classmethod
    def check_instance(cls, tx):
        if not isinstance(tx, bitcoin.core.COutPoint):
            raise proofmarshal.serialize.SerializerTypeError('Expected COutPoint; got %r' % value.__class__)

    @classmethod
    def ctx_serialize(cls, outpoint, ctx):
        serialized_tx = outpoint.serialize()

        # FIXME: should have a write variable-length bytes...
        ctx.write_varuint(len(serialized_tx))
        ctx.write_bytes(serialized_tx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        l = ctx.read_varuint()
        serialized_outpoint = ctx.read_bytes(l)
        outpoint = bitcoin.core.COutPoint.deserialize(serialized_outpoint)
        return outpoint

class TxProof(proofmarshal.proof.Proof):
    """Proof that a transaction exists in the Bitcoin blockchain"""
    __slots__ = ['tx']
    SERIALIZED_ATTRS = [('tx', CTransactionSerializer)]

    TX_HASH_XOR_PAD = b'L\xf8\x10\xb7=\xc6\x05\xfb\xe6\xc2\x15jpA\xe3p\xf4u\x0e9\xd2\xd1W1\x99\xc7r\xc72K\xd0T'

    def calc_hash(self):
        if self.is_pruned:
            return super().calc_hash()

        else:
            # Dirty trick: the hash of a TxProof is the Bitcon txhash XOR'd
            # with a fixed pad. This still guarantees global uniqueness, yet
            # lets us convert the proof hash to a bitcoin hash and back.
            return bytes([b^p for b,p in zip(self.tx.GetHash(), self.TX_HASH_XOR_PAD)])

    @property
    def txhash(self):
        """The Bitcoin transaction hash

        Available even if the TxProof is pruned!
        """
        return bytes([b^p for b,p in zip(self.hash, self.TX_HASH_XOR_PAD)])

    def verify(self, ctx):
        # FIXME
        pass

class OutPointProof(proofmarshal.proof.Proof):
    """Proof that a particular outpoint exists in the Bitcoin blockchain"""
    HASH_HMAC_KEY = b'\xf1@\xe3\x07\xa7\xc2\xc9!%u\xfb\x1a\x8d\x8b\xb9\xe1'

    __slots__ = ['txproof','n']
    SERIALIZED_ATTRS = [('txproof', TxProof),
                        ('n', proofmarshal.serialize.UInt32)]

class TxInProof:
    """Proof that a CTxIn exists in the blockchain"""
    SERIALIZED_ATTRS = [('i', proofmarshal.serialize.UInt32),
                        ('txproof', TxProof)]

    def verify(self):
        assert 0 <= self.i < len(self.txproof.tx.vin)

    @property
    def txin(self):
        """The CTxIn structure itself"""
        return self.txproof.tx.vin[self.i]

class TxOutProof:
    """Proof that a CTxOut exists in the blockchain"""
    SERIALIZED_ATTRS = [('i', proofmarshal.serialize.UInt32),
                        ('txproof', TxProof)]

    def verify(self):
        assert 0 <= self.i < len(self.txproof.tx.vout)

    @property
    def txout(self):
        """The CTxOut structure itself"""
        return self.txproof.tx.vout[self.i]
