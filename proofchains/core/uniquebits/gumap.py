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

import hashlib
import hmac

import proofmarshal.proof
import proofchains.core.uniquebits.singleuseseal
import proofmarshal.bits

class GuMap(proofmarshal.proof.ProofUnion):
    """Globally Unique Map"""
    __slots__ = []

    HASH_HMAC_KEY = None

    KEY_SERIALIZER = None
    VALUE_SERIALIZER = None

    @staticmethod
    def key2prefix(key):
        return key.hash

    SEAL_CLASS = None
    WITNESS_CLASS = None


def make_GuMap_subclass(subclass):
    @subclass.declare_union_subclass
    class UnusedPrefix(subclass):
        """A prefix whose seal hasn't been used yet"""
        used = False

        __slots__ = ('prefix', 'seal')
        SERIALIZED_ATTRS = [('prefix', proofmarshal.bits.BitsSerializer),
                            ('seal', subclass.SEAL_CLASS)]

        def verify(self):
            pass

    subclass.UnusedPrefix = UnusedPrefix


    @subclass.declare_union_subclass
    class LeafPrefix(subclass):
        """A prefix whose seal has been closed over a key:value pair"""

        __slots__ = ('key','value')
        SERIALIZED_ATTRS = [('witness', subclass.WITNESS_CLASS),
                            ('key', subclass.KEY_SERIALIZER),
                            ('value', subclass.VALUE_SERIALIZER)]

        used = False
        dirty = False

        @classmethod
        def from_unused_prefix(cls, unused_prefix, key, value, make_witness):
            # FIXME: check key is right prefix

            witness = make_witness(unused_prefix.seal, cls.__calc_sealed_hash(key, value))
            return proofmarshal.proof.ProofUnion.__new__(cls, witness=witness, key=key, value=value)


        @property
        def prefix(self):
            return self.key2prefix(self.key)

        @classmethod
        def __calc_sealed_hash(cls, key, value):
            # FIXME: this is kinda dodgy... should define some kind of
            # "canonical hash representation" in the proofmarshal serialization
            # stuff. What's the right term for this?
            try:
                key_hash = cls.KEY_SERIALIZER.get_hash(key)
            except AttributeError:
                key_hash = cls.KEY_SERIALIZER.serialize(key)

            try:
                value_hash = cls.VALUE_SERIALIZER.get_hash(value)
            except AttributeError:
                value_hash = cls.VALUE_SERIALIZER.serialize(value)

            # FIXME: we need a thought-out standard for how to do HMAC derivation for things like this
            msg = key_hash + value_hash
            return hmac.HMAC(cls.HASH_HMAC_KEY + b'leaf contents', msg, hashlib.sha256).digest()

        def verify(self):
            self.witness.verify_digest(self.__calc_sealed_hash(self.key, self.value))

    subclass.LeafPrefix = LeafPrefix


    @subclass.declare_union_subclass
    class InnerPrefix(subclass):
        """A prefix closed over left and right children"""

        __slots__ = ('prefix','left', 'right')
        SERIALIZED_ATTRS = [('prefix',  proofmarshal.bits.BitsSerializer),
                            ('witness', subclass.WITNESS_CLASS),
                            ('left',    subclass),
                            ('right',   subclass)]

        @classmethod
        def from_unused_prefix(cls, unused_prefix, left, right, make_witness):
            # FIXME: check prefixes of left and right

            witness = make_witness(unused_prefix.seal, cls.__calc_sealed_hash(left, right))
            return proofmarshal.proof.ProofUnion.__new__(cls, prefix=unused_prefix.prefix,
                                                              witness=witness,
                                                              left=left, right=right)

        @classmethod
        def __calc_sealed_hash(cls, left, right):
            # FIXME: we need a thought-out standard for how to do HMAC derivation for things like this
            msg = left.seal.hash + right.seal.hash
            return hmac.HMAC(cls.HASH_HMAC_KEY + b'inner contents', msg, hashlib.sha256).digest()

        def verify(self):
            self.witness.verify_digest(self.__calc_sealed_hash(self.left, self.right))
    subclass.InnerPrefix = InnerPrefix

    return subclass
