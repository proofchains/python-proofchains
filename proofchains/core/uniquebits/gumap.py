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

import proofmarshal.proof
import proofchains.core.uniquebits.singleuseseal
import proofmarshal.bits

from proofmarshal.serialize import HashTag

class GuMap(proofmarshal.proof.ProofUnion):
    """Globally Unique Map"""
    __slots__ = []

    HASHTAG = None

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
        __slots__ = ('prefix', 'seal')
        SERIALIZED_ATTRS = [('prefix', proofmarshal.bits.BitsSerializer),
                            ('seal', subclass.SEAL_CLASS)]

        SUB_HASHTAG = HashTag('dae47bef-d9a3-4971-a6a4-1c67c5f02c11')

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

        SUB_HASHTAG = HashTag('0c60f344-9109-4930-aec1-432c5750fcba')

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

            try:
                cls.CONTENTS_HASHTAG
            except AttributeError:
                cls.CONTENTS_HASHTAG = HashTag('59c17f37-7e26-4aea-8a5b-7c0db66af35b').derive(cls.HASHTAG)

            msg = left.seal.hash + right.seal.hash

            msg = key_hash + value_hash
            return cls.CONTENTS_HASHTAG(msg).digest()

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

        SUB_HASHTAG = HashTag('6893cac7-e834-49cd-8e95-77707b0499b5')

        @classmethod
        def from_unused_prefix(cls, unused_prefix, left, right, make_witness):
            # FIXME: check prefixes of left and right

            witness = make_witness(unused_prefix.seal, cls.__calc_sealed_hash(left, right))
            return proofmarshal.proof.ProofUnion.__new__(cls, prefix=unused_prefix.prefix,
                                                              witness=witness,
                                                              left=left, right=right)

        @classmethod
        def __calc_sealed_hash(cls, left, right):
            try:
                cls.CONTENTS_HASHTAG
            except AttributeError:
                cls.CONTENTS_HASHTAG = HashTag('b925044d-320e-4c1f-9ef8-20614d260676').derive(cls.HASHTAG)

            msg = left.seal.hash + right.seal.hash
            return cls.CONTENTS_HASHTAG(msg).digest()

        def verify(self):
            self.witness.verify_digest(self.__calc_sealed_hash(self.left, self.right))
    subclass.InnerPrefix = InnerPrefix

    return subclass
