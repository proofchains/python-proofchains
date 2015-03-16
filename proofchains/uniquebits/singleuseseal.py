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

def make_close_seal_tx_template(digest, *seals, meth='op_return', dust=600):
    """Make a transaction that would to close a seal(s) if mined

    Returns a *mutable* transaction template with all required txins and outs.
    """
    txout = None
    if meth == 'op_return':
        txout = CTxOut(0, CScript([OP_RETURN, digest]))

    elif meth == 'p2sh':
        txout = CTxOut(dust, CScript([OP_HASH160, Hash160(digest), OP_EQUAL]))

    elif meth == 'p2pkh':
        txout = CTxOut(dust, CScript([OP_DUP, OP_HASH160, Hash160(digest), OP_EQUALVERIFY, OP_CHECKSIG]))

    txins = [CTxIn(seal.outpoint) for seal in seals]

    return CTransaction(txins, [txout])
