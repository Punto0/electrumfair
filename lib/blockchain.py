#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2012 thomasv@ecdsa.org
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.



import os
import util
from bitcoin import *

MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
HEADER_SIZE = 173
CHUNK_SIZE  = 2000

class Blockchain(util.PrintError):
    '''Manages blockchain headers and their verification'''
    def __init__(self, config, network):
        self.config = config
        self.network = network
        self.headers_url = "https://electrum.fair-coin.org/download/electrumfair_headers"
        self.local_height = 0
        self.set_local_height()

    def height(self):
        return self.local_height

    def init(self):
        self.init_headers_file()
        self.set_local_height()
        self.print_error("%d blocks" % self.local_height)

    def verify_header(self, header, prev_header):
        prev_hash = self.hash_header(prev_header)
        assert prev_hash == header.get('prev_block_hash'), "prev hash mismatch: %s vs %s" % (prev_hash, header.get('prev_block_hash'))

    def verify_chain(self, chain):
        first_header = chain[0]
        prev_header = self.read_header(first_header.get('block_height') - 1)
        for header in chain:
            self.verify_header(header, prev_header)
            prev_header = header

    def verify_chunk(self, index, data):
        num = len(data) / HEADER_SIZE
        prev_header = None
        if index != 0:
            prev_header = self.read_header(index*CHUNK_SIZE - 1)
        for i in range(num):
            raw_header = data[i*HEADER_SIZE:(i+1) * HEADER_SIZE]
            header = self.deserialize_header(raw_header)
            self.verify_header(header, prev_header)
            prev_header = header

    def serialize_header(self, res):
        s = int_to_hex(res.get('version'), 4) \
            + rev_hex(res.get('prev_block_hash')) \
            + rev_hex(res.get('merkle_root')) \
            + int_to_hex(int(res.get('timestamp')), 4) \
            + rev_hex(res.get('block_hash')) \
            + rev_hex(res.get('creator')) \
            + sig_decode(res.get('creatorSignature'))
        return s

    def deserialize_header(self, s):
        hex_to_int = lambda s: int('0x' + s[::-1].encode('hex'), 16)
        h = {}
        h['version'] = hex_to_int(s[0:4])
        h['prev_block_hash'] = hash_encode(s[4:36])
        h['merkle_root'] = hash_encode(s[36:68])
        h['timestamp'] = hex_to_int(s[68:72])
        h['block_hash'] = hash_encode(s[72:104])
        h['creator'] = hash_encode(s[104:108]),
        h['creatorSignature'] = sig_encode(s[108:]),
        return h

    def hash_header(self, header):
        if header is None:
            return '0' * 64
        return header.get('block_hash')

    def path(self):
        return util.get_headers_path(self.config)

    def init_headers_file(self):
        filename = self.path()
        if os.path.exists(filename):
            return
        try:
            import urllib, socket
            socket.setdefaulttimeout(30)
            self.print_error("downloading ", self.headers_url)
            urllib.urlretrieve(self.headers_url, filename)
            self.print_error("done.")
        except Exception:
            self.print_error("download failed. creating file", filename)
            open(filename, 'wb+').close()

    def save_chunk(self, index, chunk):
        filename = self.path()
        f = open(filename, 'rb+')
        f.seek(index * CHUNK_SIZE * HEADER_SIZE)
        h = f.write(chunk)
        f.close()
        self.set_local_height()

    def save_header(self, header):
        data = self.serialize_header(header).decode('hex')
        assert len(data) == HEADER_SIZE
        height = header.get('block_height')
        filename = self.path()
        f = open(filename, 'rb+')
        f.seek(height * HEADER_SIZE)
        h = f.write(data)
        f.close()
        self.set_local_height()

    def set_local_height(self):
        name = self.path()
        if os.path.exists(name):
            h = os.path.getsize(name)/HEADER_SIZE - 1
            if self.local_height != h:
                self.local_height = h

    def read_header(self, block_height):
        name = self.path()
        if os.path.exists(name):
            f = open(name, 'rb')
            f.seek(block_height * HEADER_SIZE)
            h = f.read(HEADER_SIZE)
            f.close()
            if len(h) == HEADER_SIZE:
                h = self.deserialize_header(h)
                return h

    def get_target(self, index, chain=None):
        if index == 0:
            return 0x1d00ffff, MAX_TARGET
        first = self.read_header((index-1) * CHUNK_SIZE)
        last = self.read_header(index*CHUNK_SIZE - 1)
        if last is None:
            for h in chain:
                if h.get('block_height') == index*CHUNK_SIZE - 1:
                    last = h
        assert last is not None
        # bits to target
        bits = last.get('bits')
        bitsN = (bits >> 24) & 0xff
        assert bitsN >= 0x03 and bitsN <= 0x1d, "First part of bits should be in [0x03, 0x1d]"
        bitsBase = bits & 0xffffff
        assert bitsBase >= 0x8000 and bitsBase <= 0x7fffff, "Second part of bits should be in [0x8000, 0x7fffff]"
        target = bitsBase << (8 * (bitsN-3))
        # new target
        nActualTimespan = last.get('timestamp') - first.get('timestamp')
        nTargetTimespan = 14 * 24 * 60 * 60
        nActualTimespan = max(nActualTimespan, nTargetTimespan / 4)
        nActualTimespan = min(nActualTimespan, nTargetTimespan * 4)
        new_target = min(MAX_TARGET, (target*nActualTimespan) / nTargetTimespan)
        # convert new target to bits
        c = ("%064x" % new_target)[2:]
        while c[:2] == '00' and len(c) > 6:
            c = c[2:]
        bitsN, bitsBase = len(c) / 2, int('0x' + c[:6], 16)
        if bitsBase >= 0x800000:
            bitsN += 1
            bitsBase >>= 8
        new_bits = bitsN << 24 | bitsBase
        return new_bits, bitsBase << (8 * (bitsN-3))

    def connect_header(self, chain, header):
        '''Builds a header chain until it connects.  Returns True if it has
        successfully connected, False if verification failed, otherwise the
        height of the next header needed.'''
        chain.append(header)  # Ordered by decreasing height
        previous_height = header['block_height'] - 1
        previous_header = self.read_header(previous_height)

        # Missing header, request it
        if not previous_header:
            return previous_height

        # Does it connect to my chain?
        prev_hash = self.hash_header(previous_header)
        if prev_hash != header.get('prev_block_hash'):
            self.print_error("reorg")
            return previous_height

        # The chain is complete.  Reverse to order by increasing height
        chain.reverse()
        try:
            self.verify_chain(chain)
            self.print_error("new height:", previous_height + len(chain))
            for header in chain:
                self.save_header(header)
            return True
        except BaseException as e:
            self.print_error(str(e))
            return False

    def connect_chunk(self, idx, hexdata):
        try:
            data = hexdata.decode('hex')
            self.verify_chunk(idx, data)
            self.print_error("validated chunk %d" % idx)
            self.save_chunk(idx, data)
            return idx + 1
        except BaseException as e:
            self.print_error('verify_chunk failed', str(e))
            return idx - 1

class SignatureError(Exception):
    """Thrown if something goes wrong during signature processing."""

def sig_decode(inStr):
    """converts a DER encoded ECDSA signature into a stable length representation of 65 bytes"""

    b = inStr.decode('hex')

    #some pre-flight checks
    if ord(b[0]) != 0x30:
        raise SignatureError("DER signautres must start with 0x30")

    if ord(b[1]) < 0x42 or ord(b[1]) > 0x46:
        raise SignatureError("wrong length in DER signautre:", b[1].encode('hex'))

    # extract R
    R_len = ord(b[3])
    offset = 4

    if b[offset] == b'\x00':
        R_len -= 1
        offset += 1

    R = b[offset:R_len + offset].encode('hex')

    # extract S
    offset += R_len + 1 # skip 02 DER integer code
    S_len = ord(b[offset])

    offset += 1
    if b[offset] == b'\x00':
        S_len -= 1
        offset += 1

    S = b[offset:S_len + offset].encode('hex')

    # we encode r and s into meta_length byte for later recovery
    R_padding = 32 - R_len
    S_padding = 32 - S_len
    meta_length = R_padding + (S_padding << 4)
    return "%02x" % meta_length + "00" * R_padding + R + "00" * S_padding + S


def sig_encode(b):
    """converts a stable length representation of a ECDSA signature into a DER encoded form"""

    R_padding = ord(b[0]) & 0x0f
    S_padding = ord(b[0]) >> 4

    R_len = 32 - R_padding
    S_len = 32 - S_padding

    # reconstruct R
    offset = 1 + R_padding
    R_pad = ""
    if ord(b[offset]) >= 0x80:
        R_pad = "00"
        R_len += 1

    R_ret = "02%02x%s" % (R_len, R_pad)
    R_ret += b[offset:offset + 32 - R_padding].encode('hex')

    # reconsturct S
    offset += 32 - R_padding + S_padding
    S_pad = ""
    if ord(b[offset]) >= 0x80:
        S_pad = "00"
        S_len += 1

    S_ret = "02%02x%s" % (S_len, S_pad)
    S_ret += b[offset:offset + 32 - S_padding].encode('hex')

    return "30%02x" % (R_len + S_len + 4) + R_ret + S_ret
