#!/usr/bin/env python
# extract-bitcoincore-mkey.py -- Bitcoin wallet master key extractor
# This file is reference btcrecover and bitcoin2john.py
# If this has helped you, then please donate to support my further research.
# My Bitcoin address:
#
# 18H2fTnpdMbPyusKEUU3Z67PtA2uQTBQNW
#
# Thank You!

import binascii
from logaid import log
import struct
import os
import sqlite3
import sys

class Extracter:

    def __init__(self, wallet_filename):
        self.wallet_filename = wallet_filename

    def get_old_wallet_info(self):
        mkey = None
        def align_32bits(i):
            m = i % 4
            return i if m == 0 else i + 4 - m

        with open(self.wallet_filename, "rb") as wallet_file:
            wallet_file.seek(12)
            assert wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00", "is a Btree v9 file"
            wallet_file.seek(20)
            page_size = struct.unpack(b"<I", wallet_file.read(4))[0]
            wallet_file_size = os.path.getsize(wallet_filename)
            for page_base in range(page_size, wallet_file_size, page_size):
                wallet_file.seek(page_base + 20)
                (item_count, first_item_pos, btree_level, page_type) = struct.unpack(b"< H H B B", wallet_file.read(6))
                if page_type != 5 or btree_level != 1:
                    continue
                pos = align_32bits(page_base + first_item_pos)
                wallet_file.seek(pos)
                for i in range(item_count):
                    (item_len, item_type) = struct.unpack(b"< H B", wallet_file.read(3))
                    if item_type & ~0x80 == 1:
                        if item_type == 1:
                            if i % 2 == 0:
                                value_pos = pos + 3
                                value_len = item_len

                            elif item_len == 9 and wallet_file.read(item_len) == b"\x04mkey\x01\x00\x00\x00":
                                wallet_file.seek(value_pos)
                                mkey = wallet_file.read(value_len)
                                break
                        pos = align_32bits(pos + 3 + item_len)
                    else:
                        pos += 12
                    if i + 1 < item_count:
                        assert pos < page_base + page_size, "next item is located in current page"
                        wallet_file.seek(pos)
                else:
                    continue
                break
        if not mkey:
            log.warning("This wallet is not encrypted.")
            return dict()
        encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)
        wallet_info = {}
        wallet_info['encrypted_master_key'] = binascii.hexlify(encrypted_master_key).decode('ascii')
        wallet_info['salt'] = binascii.hexlify(salt).decode('ascii')
        wallet_info['method'] = method
        wallet_info['iter_count'] = iter_count
        return wallet_info

    def get_new_wallet_info(self) -> dict:
        mkey = None
        try:
            self.wallet_conn = sqlite3.connect(wallet_filename)
            for key, value in self.wallet_conn.execute('SELECT * FROM main'):
                if b"\x04mkey\x01\x00\x00\x00" in key:
                    mkey = value
            self.wallet_conn.close()
        except Exception as e:
            log.error("ERROR:",e)
            return dict()
        if not mkey:
            log.warning("This wallet is not encrypted.")
            return dict()
        encrypted_master_key, salt, method, iter_count = struct.unpack_from("< 49p 9p I I", mkey)
        wallet_info = {}
        wallet_info['encrypted_master_key'] = binascii.hexlify(encrypted_master_key).decode('ascii')
        wallet_info['salt'] = binascii.hexlify(salt).decode('ascii')
        wallet_info['method'] = method
        wallet_info['iter_count'] = iter_count
        return wallet_info

    def dispose_wallet_info(self,wallet_info):
        if not wallet_info:
            return
        if wallet_info['method'] != 0:
            log.error("This wallet uses unknown key derivation method.")
            return
        cry_rounds = wallet_info['iter_count']
        cry_salt = wallet_info['salt']
        cry_master = wallet_info['encrypted_master_key'][-64:]  # last two AES blocks are enough
        sys.stdout.write("$bitcoin$%s$%s$%s$%s$%s$2$00$2$00\n" %(len(cry_master), cry_master, len(cry_salt), cry_salt, cry_rounds))

    def is_old_wallet(self):
        with open(self.wallet_filename, "rb") as wallet_file:
            wallet_file.seek(12)
            if wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00":
                return True
            wallet_file.seek(0)
            if wallet_file.read(16) == b"SQLite format 3\0":
                return False
            raise ValueError(f"error: file is not a Bitcoin Core wallet. {self.wallet_filename}")

    def start_run(self):
        if self.is_old_wallet():
            wallet_info = self.get_old_wallet_info()
        else:
            wallet_info = self.get_new_wallet_info()
        self.dispose_wallet_info(wallet_info)


if __name__ == '__main__':
    # wallet_filename = r"D:\MyApp\BTC\btc_data\test_1\wallet.dat"
    wallet_filename = ""
    if not wallet_filename:
        wallet_filename = sys.argv[1]
    extract = Extracter(wallet_filename)
    extract.start_run()
