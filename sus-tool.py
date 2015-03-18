#!/usr/bin/env python3
#
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

"""Single-use seal tool"""

import argparse
import collections
import logging

import bitcoin.rpc

from bitcoin.core import x, lx, b2x, b2lx, CTransaction

from proofchains.core.bitcoin import TxProof, TxInProof, TxOutProof
from proofchains.core.uniquebits.singleuseseal import BitcoinSingleUseSeal, BitcoinSealWitness
from proofchains.uniquebits.singleuseseal import make_close_seal_tx_template

class ParseCOutPointArg(argparse.Action):
    @staticmethod
    def str_to_COutPoint(str_outpoint, parser):
        try:
            if str_outpoint.count(':') != 1:
                raise ValueError
            str_txid, str_n = str_outpoint.split(':')

            txid = bitcoin.core.lx(str_txid)
            n = int(str_n)
            return bitcoin.core.COutPoint(txid, n)
        except ValueError as exp:
            parser.exit('Bad outpoint %r: %s' % (str_outpoint, exp))

    def __call__(self, parser, args, values, option_string=None):

        values = self.str_to_COutPoint(values, parser)
        setattr(args, self.dest, values)

class ParseDigestArg(argparse.Action):
    @staticmethod
    def str_to_digest(str_digest, parser):
        try:
            digest = bytes.fromhex(str_digest)
            if len(digest) != 32:
                 raise ValueError('Length != 32')
            return digest
        except ValueError as exp:
            parser.exit('Bad digest %r: %s' % (str_digest, exp))

    def __call__(self, parser, args, values, option_string=None):
        values = self.str_to_digest(values, parser)
        setattr(args, self.dest, values)


parser = argparse.ArgumentParser(
        description="Single-Use-Seal Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument('-t', action='store_true',
                    dest='testnet',
                    help='Enable testnet')
parser.add_argument('-n', action='store_true',
                    dest='dryrun',
                    help="Dry-run; don't actually send the transactions")
parser.add_argument("-q","--quiet",action="count",default=0,
                    help="Be more quiet.")
parser.add_argument("-v","--verbose",action="count",default=0,
                    help="Be more verbose. Both -v and -q may be used multiple times.")

subparsers = parser.add_subparsers()



mkseal_parser = subparsers.add_parser('mkseal',
            help='Make a single-use-seal from an outpoint')
mkseal_parser.add_argument('outpoint', metavar='TXID:N',
        action=ParseCOutPointArg,
        help='Outpoint')
mkseal_parser.add_argument('seal_fd', type=argparse.FileType('xb'), metavar='FILE',
        help='Seal file')

def cmd_mkseal(args):
    btc_seal = BitcoinSingleUseSeal(outpoint=args.outpoint)
    args.seal_fd.write(btc_seal.serialize())

mkseal_parser.set_defaults(cmd_func=cmd_mkseal)



mkclosetx_parser = subparsers.add_parser('mkclosetx',
            help='Make a transaction that would close one or more seals over a digest')
mkclosetx_parser.add_argument('digest', metavar='DIGEST',
        action=ParseDigestArg,
        help='Hash digest (hex)')
mkclosetx_parser.add_argument('seal_fds', type=argparse.FileType('rb'), metavar='SEAL-FILE',
        nargs='+',
        help='Seal file(s)')

mkclosetx_meth_group = mkclosetx_parser.add_mutually_exclusive_group()
mkclosetx_meth_group.add_argument('--op-return',
        action='store_const', dest='meth', const='op_return',
        default='op_return',
        help='Close seal with a OP_RETURN output (default)')
mkclosetx_meth_group.add_argument('--p2sh',
        action='store_const', dest='meth', const='p2sh',
        help='Close seal with a P2SH output')
mkclosetx_meth_group.add_argument('--p2pkh',
        action='store_const', dest='meth', const='p2pkh',
        help='Close seal with a P2PKH output')

def cmd_mkclosetx(args):
    seals = collections.OrderedDict()
    for seal_fd in args.seal_fds:
        seal = BitcoinSingleUseSeal.deserialize(seal_fd.read())
        if seal in seals:
            args.parser.error("Duplicate seal: '%s' duplicates '%s'" % \
                              (seal_fd.name, seals[seal].name))
        seals[seal] = seal_fd

        logging.debug('Closing seal %s on outpoint %s:%d' % \
                      (b2x(seal.hash), b2lx(seal.outpoint.hash), seal.outpoint.n))
    seals = seals.keys()

    close_tx = make_close_seal_tx_template(args.digest, *seals, meth=args.meth)

    print(b2x(close_tx.serialize()))

mkclosetx_parser.set_defaults(cmd_func=cmd_mkclosetx)


mkwitness_parser = subparsers.add_parser('mkwitness',
            help='Witness the fact that one or more seals were closed')
mkwitness_parser.add_argument('seal_fds', type=argparse.FileType('rb'), metavar='SEAL-FILE',
        nargs='+',
        help='Seal file(s)')

mkwitness_tx_group = mkwitness_parser.add_mutually_exclusive_group(required=True)
mkwitness_tx_group.add_argument('--txid',
        action='store', type=lx,
        help='Specify closing tx by txid')
mkwitness_tx_group.add_argument('--tx',
        action='store', type=x,
        help='Provide closing tx as hex bytes')

def cmd_mkwitness(args):
    tx = None
    if args.tx is not None:
        serialized_tx = args.tx
        tx = CTransaction.deserialize(serialized_tx)

    else:
        tx = args.proxy.getrawtransaction(args.txid)

    txproof = TxProof(tx=tx)

    for seal_fd in args.seal_fds:
        seal = BitcoinSingleUseSeal.deserialize(seal_fd.read())

        txinproof = None
        txoutproof = None
        for i, txin in enumerate(txproof.tx.vin):
            if txin.prevout == seal.outpoint:
                txinproof = TxInProof(i=i, txproof=txproof)
                txoutproof = TxOutProof(i=0, txproof=txproof)
                break

        else:
            args.parser.error("Seal '%s' not closed by this transaction" % seal_fd.name)

        witness = BitcoinSealWitness(seal=seal, txinproof=txinproof, txoutproof=txoutproof)

        witness_filename = seal_fd.name + '.witness'
        logging.info("Creating witness file '%s'" % witness_filename)
        with open(seal_fd.name + '.witness', 'xb') as witness_fd:
            witness_fd.write(witness.serialize())

mkwitness_parser.set_defaults(cmd_func=cmd_mkwitness)


verifywitness_parser = subparsers.add_parser('verifywitness',
        help='Verify a witness to a single-use-seal being closed')
verifywitness_parser.add_argument('witness_fd', metavar='WITNESS-FILE',
        type=argparse.FileType('rb'),
        help='Witness file')
verifywitness_parser.add_argument('-d', metavar='DIGEST',
        dest='digest',
        action=ParseDigestArg,
        help='Hash digest')
verifywitness_parser.add_argument('--seal-file', metavar='SEAL-FILE',
        type=argparse.FileType('rb'),
        help='Seal file')
verifywitness_parser.add_argument('--seal-id', metavar='SEAL-ID',
        action=ParseDigestArg,
        help='Seal hash (hex)')
verifywitness_parser.add_argument('-l','--local',
        action='store_true',
        help="Only verify local self-consistency; don't attempt to determine if the witness tx is in the chain")

def cmd_verifywitness(args):
    witness = BitcoinSealWitness.deserialize(args.witness_fd.read())

    # FIXME: implement --local
    witness.verify()

    if args.digest is not None:
        witness.verify_digest(args.digest)

    # FIXME: seal and seal hash

verifywitness_parser.set_defaults(cmd_func=cmd_verifywitness)


sealinfo_parser = subparsers.add_parser('sealinfo',
        help='Show information about a seal')
sealinfo_parser.add_argument('seal_fd', metavar='SEAL-FILE',
        type=argparse.FileType('rb'),
        help='Seal file')

def cmd_sealinfo(args):
    seal = BitcoinSingleUseSeal.deserialize(args.seal_fd.read())

    print('Hash:\t\t%s' % b2x(seal.hash))
    print('OutPoint:\t%s:%d' % (b2lx(seal.outpoint.hash), seal.outpoint.n))

sealinfo_parser.set_defaults(cmd_func=cmd_sealinfo)


witnessinfo_parser = subparsers.add_parser('witnessinfo',
        help='Show information about a witness')
witnessinfo_parser.add_argument('witness_fd', metavar='WITNESS-FILE',
        type=argparse.FileType('rb'),
        help='Witness file')

def cmd_witnessinfo(args):
    witness = BitcoinSealWitness.deserialize(args.witness_fd.read())

    print('Hash:\t\t%s' % b2x(witness.hash))
    print('Txid:\t\t%s' % b2lx(witness.txinproof.txproof.txhash))
    print('Seal Hash:\t%s' % b2x(witness.seal.hash))
    print('Seal OutPoint:\t%s:%d' % (b2x(witness.seal.outpoint.hash), witness.seal.outpoint.n))

witnessinfo_parser.set_defaults(cmd_func=cmd_witnessinfo)



args = parser.parse_args()
args.parser = parser

# Setup logging

args.verbosity = args.verbose - args.quiet

if args.verbosity == 1:
    logging.root.setLevel(logging.INFO)
elif args.verbosity >= 2:
    logging.root.setLevel(logging.DEBUG)
elif args.verbosity == 0:
    logging.root.setLevel(logging.WARNING)
elif args.verbosity <= -1:
    logging.root.setLevel(logging.ERROR)

if args.testnet:
    bitcoin.SelectParams('testnet')

args.proxy = bitcoin.rpc.Proxy()

if hasattr(args, 'cmd_func'):
    args.cmd_func(args)

else:
    parser.error('No command specified')
