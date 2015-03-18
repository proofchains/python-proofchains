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

"""Single use seals

Similar to those serialized zip-ties and tamper-evident bags used to verify the
authenticity of physical items, single use seals are special cryptographic
constructs that have a unique hash and can be applied to seal another hash
exactly once, producing a seal witness.

"""

import proofmarshal.proof
import proofmarshal.serialize

import proofchains.core.bitcoin

from bitcoin.core.script import CScript, OP_RETURN, OP_HASH160, OP_EQUAL, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG
from bitcoin.core import Hash160

class SingleUseSeal(proofmarshal.proof.Proof):
    """A specific single use seal

    """
    __slots__ = []

class SealWitness(proofmarshal.proof.Proof):
    """Witness to the use of a single use seal"""
    __slots__ = []


### Fake seals!

class FakeSingleUseSeal(SingleUseSeal):
    """Fake SUS that simply hashes the data to be witnessed in advance"""
    __slots__ = []
    SERIALIZED_ATTRS = [('committed_hash', proofmarshal.serialize.Digest)]

    HASH_HMAC_KEY = bytes.fromhex('dcd8bf2ec0640b9290e5c0874df3ce14')

class FakeSealWitness(SealWitness):
    """Witness to a FakeSingleUseSeal"""
    __slots__ = ['seal']
    SERIALIZED_ATTRS = [('seal', FakeSingleUseSeal)]

    HASH_HMAC_KEY = bytes.fromhex('77581acb3212ad66fafc597e6154ec92')

    def verify_hash(self, hash):
        assert self.seal.committed_hash == hash

### Bitcoin implementation

class BitcoinSingleUseSeal(SingleUseSeal):
    """Single Use Seal implemented via Bitcoin

    Simply an outpoint in the Bitcoin blockchain that is later spent in a
    specific way.
    """
    __slots__ = ['outpoint']
    SERIALIZED_ATTRS = [('outpoint', proofchains.core.bitcoin.COutPointSerializer)]

    HASH_HMAC_KEY = bytes.fromhex('d2099c418f7959d7663263866540648a')


class BitcoinSealWitness(SingleUseSeal):
    """Witness to the use of a BitcoinSingleUseSeal"""
    __slots__ = ['seal','txoutproof']

    SERIALIZED_ATTRS = [('seal',      BitcoinSingleUseSeal),
                        ('txinproof', proofchains.core.bitcoin.TxInProof),
                        ('txoutproof', proofchains.core.bitcoin.TxOutProof)]

    HASH_HMAC_KEY = bytes.fromhex('4c542f6a89da6520534e4a2095fa24fd')

    def verify(self):
        assert self.seal.outpoint == self.txinproof.txin.prevout
        assert self.txinproof.txproof == self.txoutproof.txproof

    # FIXME: verify_digest() or verify_hash()?
    def verify_digest(self, digest):
        assert len(digest) == 32
        # Avoid the consensus issues of parsing the scriptPubKey by generating
        # one ourselves, and then doing a byte-for-byte comparison.
        # Additionally we support P2SH and P2PKH for censorship resistance.
        actual_scriptPubKey = self.txoutproof.txout.scriptPubKey
        assert (actual_scriptPubKey == CScript([OP_RETURN, digest]) or
                actual_scriptPubKey == CScript([OP_HASH160, Hash160(digest), OP_EQUAL]) or
                actual_scriptPubKey == CScript([OP_DUP, OP_HASH160, Hash160(digest), OP_EQUALVERIFY, OP_CHECKSIG]))
