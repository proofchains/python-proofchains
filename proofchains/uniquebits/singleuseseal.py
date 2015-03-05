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

"""Single use seals - non-consensus-critical functionality"""

from bitcoin.core.script import CScript, OP_RETURN, OP_HASH160, OP_EQUAL, OP_DUP, OP_EQUALVERIFY, OP_CHECKSIG
from bitcoin.core import Hash160, CTransaction, CTxIn, CTxOut

def make_witness_tx(seal, hash, meth='op_return', dust=600):
    txout = None
    if meth == 'op_return':
        txout = CTxOut(0, CScript([OP_RETURN, hash]))

    elif meth == 'p2sh':
        txout = CTxOut(dust, CScript([OP_HASH160, Hash160(hash), OP_EQUAL]))

    elif meth == 'p2pkh':
        txout = CTxOut(dust, CScript([OP_DUP, OP_HASH160, Hash160(hash), OP_EQUALVERIFY, OP_CHECKSIG]))

    return CTransaction([CTxIn(seal.outpoint)],
                        [txout])
