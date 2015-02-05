# Copyright (C) 2015 Peter Todd <pete@petertodd.org>
#
# This file is part of python-proofmarshal.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-proofmarshal, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

import binascii
import copy
import hashlib
import hmac

from proofmarshal.serialize import HashingSerializer, BytesSerializationContext, SerializerTypeError

"""Proof representation

Provides Proof and PrunedProof classes to represent complex, immutable,
cryptographic proofs that may have dependent proofs pruned away.

"""

class Proof(HashingSerializer):
    """Base class for all proof objects

    Proofs are Structs that support pruning, automatically track dependencies,
    and can be (partially) validated.

    """
    HASH_HMAC_KEY = None

    __slots__ = ['is_pruned', 'is_fully_pruned','__orig_instance','hash']
    SERIALIZED_ATTRS = ()

    def __new__(cls, **kwargs):
        """Basic creation/initialization"""
        serialized_attrs = {name:ser_cls for (name, ser_cls) in cls.SERIALIZED_ATTRS}

        is_pruned = False
        self = object.__new__(cls)
        for name, ser_cls in serialized_attrs.items():
            value = kwargs[name]
            ser_cls.check_instance(value)
            object.__setattr__(self, name, value)

            if issubclass(ser_cls, Proof):
                is_pruned |= value.is_pruned

        object.__setattr__(self, 'is_fully_pruned', False)
        object.__setattr__(self, 'is_pruned', is_pruned)
        object.__setattr__(self, '_Proof__orig_instance', None)
        return self

    @classmethod
    def check_instance(cls, instance):
        """Check that an instance can be serialized by this serializer

        Raises SerializerTypeError if not
        """
        # FIXME

    def __eq__(self, other):
        if isinstance(other, Proof):
            return self.hash == other.hash

        else:
            return NotImplemented

    def __setattr__(self, name, value):
        raise TypeError('%s instances are immutable' % self.__class__.__qualname__)

    def __delattr__(self, name):
        raise TypeError('%s instances are immutable' % self.__class__.__qualname__)

    def prune(self):
        """Create a pruned version of this proof

        Returns a new instance with all attributes removed. A reference to the
        original instance is maintained, and used to unprune attributes as they
        are used.
        """

        # Start with a blank instance with absolutely no attributes set at all.
        pruned_self = object.__new__(self.__class__)

        object.__setattr__(pruned_self, '_Proof__orig_instance', self)
        object.__setattr__(pruned_self, 'is_fully_pruned', True)
        object.__setattr__(pruned_self, 'is_pruned', True)

        return pruned_self

    def __getattr__(self, name):
        # Special-case hash to let it be calculated lazily
        if name == 'hash':
            hash = self.calc_hash()
            object.__setattr__(self, 'hash', hash)
            return hash

        if self.__orig_instance is None:
            # Don't have the original instance. Is this an attribute we should
            # have?
            if name in ():
                # FIXME: raise pruning error
                raise NotImplementedError
            else:
                raise AttributeError("%r object has no attribute %r" % (self.__class__, name))

        else:
            assert self.is_pruned

            # We are pruned. Try getting that attribute from the original,
            # non-pruned, instance. If it doesn't exist, the above code will throw
            # an exception as expected.
            value = getattr(self.__orig_instance, name)

            # If the value is itself a proof, prune it to track dependencies
            # recursively.
            if isinstance(value, Proof):
                value = value.prune()

            # For efficiency, we can now add that value to self to avoid going
            # through this process over again.
            object.__setattr__(self, name, value)

            # We succesfully brought something back into view, which means this
            # instance must not be fully pruned.
            object.__setattr__(self, 'is_fully_pruned', False)
            return value

    def calc_hash(self):
        if self.__orig_instance is not None:
            # Avoid unpruning unnecessarily
            return self.__orig_instance.hash

        else:
            # FIXME: catch pruning errors; should never happen
            hasher = hmac.HMAC(self.HASH_HMAC_KEY, b'', hashlib.sha256)

            for attr_name, ser_cls in self.SERIALIZED_ATTRS:
                attr_value = getattr(self, attr_name)

                if issubclass(ser_cls, HashingSerializer):
                    hasher.update(ser_cls.get_hash(attr_value))

                else:
                    hasher.update(ser_cls.serialize(attr_value))

            return hasher.digest()

    def get_hash(self):
        return self.hash

    def _ctx_serialize(self, ctx):
        for attr_name, ser_cls in self.SERIALIZED_ATTRS:
            attr = getattr(self, attr_name)
            ser_cls.ctx_serialize(attr, ctx)

    def ctx_serialize(self, ctx):
        if self.is_fully_pruned:
            ctx.write_bool(True)
            ctx.write_bytes(self.hash)

        else:
            ctx.write_bool(False)
            self._ctx_serialize(ctx)


    def serialize(self):
        """Serialize to bytes"""
        ctx = BytesSerializationContext()
        self.ctx_serialize(ctx)
        return ctx.getbytes()

    @classmethod
    def _ctx_deserialize(cls, ctx):
        kwargs = {}

        for name, ser_cls in cls.SERIALIZED_ATTRS:
            value = ser_cls.ctx_deserialize(ctx)
            kwargs[name] = value

        return Proof.__new__(cls, **kwargs)

    @classmethod
    def ctx_deserialize(cls, ctx):
        fully_pruned = ctx.read_bool()


        if fully_pruned:
            self = object.__new__(cls)

            hash = ctx.read_bytes(32) # FIXME
            object.__setattr__(self, 'hash', hash)

            object.__setattr__(self, 'is_fully_pruned', True)
            object.__setattr__(self, 'is_pruned', True)
            object.__setattr__(self, '_Proof__orig_instance', None)

            return self

        else:
            return cls._ctx_deserialize(ctx)

    def __repr__(self):
        # FIXME: better way to get a fully qualified name?
        return '%s.%s(<%s>)' % (self.__class__.__module__, self.__class__.__qualname__,
                                binascii.hexlify(self.hash).decode('utf8'))

class ProofUnion(Proof):
    """Serialization of unions of Proofs"""
    __slots__ = []

    UNION_CLASSES = None

    @classmethod
    def check_instance(cls, value):
        for cls in cls.UNION_CLASSES:
            if isinstance(value, cls):
                break
        else:
            raise SerializerTypeError('Class %r is not part of the %r union' % (value.__class__, cls))

    @classmethod
    def declare_union_subclass(cls, subclass):
        """Class decorator to make a subclass part of a ProofUnion

        Warning! Declaration order is consensus-critical.
        """
        if not issubclass(subclass, ProofUnion):
            raise TypeError('Only ProofUnion subclasses can be part of a ProofUnion')

        if cls.UNION_CLASSES is None:
            cls.UNION_CLASSES = []

        cls.UNION_CLASSES.append(subclass)

        return subclass

    def _ctx_serialize(self, ctx):
        for i,cls in enumerate(self.UNION_CLASSES):
            if isinstance(self, cls):
                ctx.write_varuint(i)
                break

        else:
            raise SerializerTypeError('bad class')

        super()._ctx_serialize(ctx)

    @classmethod
    def ctx_deserialize(cls, ctx):
        raise NotImplementedError
