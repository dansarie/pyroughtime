#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyroughtime
# Copyright (C) 2019-2020 Marcus Dansarie <marcus@dansarie.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import base64
import ed25519
import datetime
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

class RoughtimeError(Exception):
    'Represents an error that has occured in the Roughtime client.'
    def __init__(self, message):
        super(RoughtimeError, self).__init__(message)

class RoughtimeServer:
    '''
    Implements a Roughtime server that provides authenticated time.

    Args:
        cert (bytes): A base64 encoded Roughtime CERT packet containing a
                delegate certificate signed with a long-term key.
        pkey (bytes): A base64 encoded ed25519 private key.
        radi (int): The time accuracy (RADI) that the server should report.

    Raises:
        RoughtimeError: If cert and pkey do not represent a valid ed25519
                certificate pair.
    '''
    CERTIFICATE_CONTEXT = b'RoughTime v1 delegation signature--\x00'
    SIGNED_RESPONSE_CONTEXT = b'RoughTime v1 response signature\x00'
    def __init__(self, cert, pkey, radi=100000):
        cert = base64.b64decode(cert)
        pkey = base64.b64decode(pkey)
        if len(cert) != 152:
            raise RoughtimeError('Wrong CERT length.')
        self.cert = RoughtimePacket('CERT', cert)
        self.pkey = ed25519.SigningKey(pkey)
        self.radi = int(radi)

        # Ensure that the CERT and private key are a valid pair.
        pubkey = ed25519.VerifyingKey(self.cert.get_tag('DELE') \
                .get_tag('PUBK').get_value_bytes())
        testsign = self.pkey.sign(RoughtimeServer.SIGNED_RESPONSE_CONTEXT)
        try:
            pubkey.verify(testsign, RoughtimeServer.SIGNED_RESPONSE_CONTEXT)
        except:
            raise RoughtimeError('CERT and pkey arguments are not a valid '
                    + 'certificate pair.')

    def start(self, ip, port):
        '''
        Starts the Roughtime server.

        Args:
            ip (str): The IP address the server should bind to.
            port (int): The UDP port the server should bind to.
        '''
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))
        self.sock.settimeout(0.001)
        self.run = True
        self.thread = threading.Thread(target=RoughtimeServer.__recv_thread,
                args=(self,))
        self.thread.start()

    def stop(self):
        'Stops the Roughtime server.'
        if self.run == False:
            return
        self.run = False
        self.thread.join()
        self.sock.close()
        self.thread = None
        self.sock = None

    @staticmethod
    def __clp2(x):
        'Returns the next power of two.'
        x -= 1
        x |= x >>  1
        x |= x >>  2
        x |= x >>  4
        x |= x >>  8
        x |= x >> 16
        return x + 1

    @staticmethod
    def __construct_merkle(nonces, prev=None, order=None):
        'Builds a Merkle tree.'
        # First call:  and calculate order
        if prev == None:
            # Hash nonces.
            nonces = [hashlib.sha512(b'\x00' + x).digest()[:32] for x in nonces]
            # Calculate next power of two.
            size = RoughtimeServer.__clp2(len(nonces))
            # Extend nonce list to the next power of two.
            nonces += [os.urandom(64) for x in range(size - len(nonces))]
            # Calculate list order
            order = 0
            while size & 1 == 0:
                order += 1
                size >>= 1
            return RoughtimeServer.__construct_merkle(nonces, [nonces], order)

        if order == 0:
            return prev

        out = []
        for n in range(1 << (order - 1)):
            out.append(hashlib.sha512(b'\x01' + nonces[n * 2]
                    + nonces[n * 2 + 1]).digest()[:32])

        prev.append(out)
        return RoughtimeServer.__construct_merkle(out, prev, order - 1)

    @staticmethod
    def __construct_merkle_path(merkle, index):
        'Returns the Merkle tree path for a nonce index.'
        out = b''
        while len(merkle[0]) > 1:
            out += merkle[0][index ^ 1]
            merkle = merkle[1:]
            index >>= 1
        return out

    @staticmethod
    def __datetime_to_timestamp(dt):
        timestamp = (dt.date() - datetime.date(1858, 11, 17)).days << 40
        timestamp += dt.time().hour * 3600000000
        timestamp += dt.time().minute * 60000000
        timestamp += dt.time().second * 1000000
        timestamp += dt.time().microsecond
        return timestamp

    @staticmethod
    def __recv_thread(ref):
        while ref.run:
            try:
                data, addr = ref.sock.recvfrom(1500)
            except socket.timeout:
                continue

            # Ignore requests shorter than 1024 bytes.
            if len(data) < 1024:
                print("Bad length.")
                continue

            try:
                request = RoughtimePacket(packet=data)
            except:
                print("Bad packet.")
                continue

            # Ensure request contains a proper nonce.
            if request.contains_tag('NONC') == False or request.contains_tag('VER') == False:
                print(request.tags)
                print("Missing VER or NONC.")
                continue
            nonc = request.get_tag('NONC').get_value_bytes()
            if len(nonc) != 64:
                print("NONC != 64")
                continue

            noncelist = [nonc]
            merkle = RoughtimeServer.__construct_merkle(noncelist)
            path_bytes = RoughtimeServer.__construct_merkle_path(merkle, 0)

            # Construct reply.
            reply = RoughtimePacket()
            reply.add_tag(ref.cert)
            reply.add_tag(request.get_tag('NONC'))
            reply.add_tag(RoughtimeTag('VER', RoughtimeTag.uint32_to_bytes(0x80000003)))

            # Single nonce Merkle tree.
            indx = RoughtimeTag('INDX')
            indx.set_value_uint32(0)
            reply.add_tag(indx)
            path = RoughtimeTag('PATH')
            path.set_value_bytes(path_bytes)
            reply.add_tag(path)

            srep = RoughtimePacket('SREP')

            root = RoughtimeTag('ROOT', merkle[-1][0])
            srep.add_tag(root)

            midp = RoughtimeTag('MIDP')
            midp.set_value_uint64(RoughtimeServer.__datetime_to_timestamp(\
                    datetime.datetime.now()))
            srep.add_tag(midp)

            radi = RoughtimeTag('RADI')
            radi.set_value_uint32(ref.radi)
            srep.add_tag(radi)
            reply.add_tag(srep)

            sig = RoughtimeTag('SIG', ref.pkey.sign(
                    RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                            + srep.get_value_bytes()))
            reply.add_tag(sig)

            ref.sock.sendto(reply.get_value_bytes(), addr)

    @staticmethod
    def create_key():
        '''
        Generates a long-term key pair.

        Returns:
            priv (bytes): A base64 encoded ed25519 private key.
            publ (bytes): A base64 encoded ed25519 public key.
        '''
        priv, publ = ed25519.create_keypair()
        return base64.b64encode(priv.to_bytes()), \
                base64.b64encode(publ.to_bytes())

    @staticmethod
    def create_delegate_key(priv, mint=None, maxt=None):
        '''
        Generates a Roughtime delegate key signed by a long-term key.

        Args:
            priv (bytes): A base64 encoded ed25519 private key.
            mint (int): Start of the delegate key's validity tile in
                    microseconds since the epoch.
            maxt (int): End of the delegate key's validity tile in
                    microseconds since the epoch.

        Returns:
            cert (bytes): A base64 encoded Roughtime CERT packet.
            dpriv (bytes): A base64 encoded ed25519 private key.
        '''
        if mint == None:
            mint = RoughtimeServer.__datetime_to_timestamp(\
                    datetime.datetime.now())
        if maxt == None or maxt <= mint:
            maxt = RoughtimeServer.__datetime_to_timestamp(\
                    datetime.datetime.now() + datetime.timedelta(days=30))
        priv = ed25519.SigningKey(priv, encoding='base64')
        dpriv, dpubl = ed25519.create_keypair()
        mint_tag = RoughtimeTag('MINT')
        maxt_tag = RoughtimeTag('MAXT')
        mint_tag.set_value_uint64(mint)
        maxt_tag.set_value_uint64(maxt)
        pubk = RoughtimeTag('PUBK')
        pubk.set_value_bytes(dpubl.to_bytes())
        dele = RoughtimePacket(key='DELE')
        dele.add_tag(mint_tag)
        dele.add_tag(maxt_tag)
        dele.add_tag(pubk)

        delesig = priv.sign(RoughtimeServer.CERTIFICATE_CONTEXT
                + dele.get_value_bytes())
        sig = RoughtimeTag('SIG', delesig)

        cert = RoughtimePacket('CERT')
        cert.add_tag(dele)
        cert.add_tag(sig)

        return base64.b64encode(cert.get_value_bytes()), \
                base64.b64encode(dpriv.to_bytes())

    @staticmethod
    def test_server():
        '''
        Starts a Roughtime server listening on 127.0.0.1, port 2002 for
        testing.

        Returns:
            serv (RoughtimeServer): The server instance.
            publ (bytes): The server's public long-term key.
        '''
        priv, publ = RoughtimeServer.create_key()
        cert, dpriv = RoughtimeServer.create_delegate_key(priv)
        serv = RoughtimeServer(cert, dpriv)
        serv.start('127.0.0.1', 2002)
        return serv, publ

class RoughtimeClient:
    '''
    Queries Roughtime servers for the current time and authenticates the
    replies.

    Args:
        max_history_len (int): The number of previous replies to keep.
    '''
    def __init__(self, max_history_len=100):
        self.prev_replies = []
        self.max_history_len = max_history_len

    @staticmethod
    def midp_to_datetime(midp):
        if midp == 0xffffffffffffffff:
            return None
        if midp < 30000000000000000:
            return datetime.datetime.utcfromtimestamp(midp / 1E6)
        ret = datetime.datetime.fromordinal(678576 + (midp >> 40))
        ret += datetime.timedelta(microseconds=midp&0xffffffffff)
        return ret

    @staticmethod
    def __udp_query(address, port, packet, timeout):
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_DGRAM):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(0.001)
            try:
                sock.sendto(packet, (sockaddr[0], sockaddr[1]))
            except Exception as ex:
                # Try next IP on failure.
                sock.close()
                continue

            # Wait for reply
            start_time = time.monotonic()
            while time.monotonic() - start_time < timeout:
                try:
                    data, repl = sock.recvfrom(1500)
                    repl_addr = repl[0]
                    repl_port = repl[1]
                except socket.timeout:
                    continue
                if repl_addr == sockaddr[0] and repl_port == sockaddr[1]:
                    break
            rtt = time.monotonic() - start_time
            sock.close()
            if rtt >= timeout:
                # Try next IP on timeout.
                continue
            # Break out of loop if successful.
            break
        if rtt >= timeout:
            raise RoughtimeError('Timeout while waiting for reply.')
        reply = RoughtimePacket(packet=data)

        return reply, rtt, data

    @staticmethod
    def __tcp_query(address, port, packet, timeout):
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((sockaddr[0], sockaddr[1]))
                sock.sendall(packet)
            except Exception as ex:
                # Try next IP on failure.
                sock.close()
                continue

            # Wait for reply
            start_time = time.monotonic()
            buf = bytes()
            while time.monotonic() - start_time < timeout:
                try:
                    buf += sock.recv(4096)
                except socket.timeout:
                    continue
                if len(buf) < 12:
                    continue
                (magic, repl_len) = struct.unpack('<QI', buf[:12])
                if magic != 0x4d49544847554f52:
                    raise RoughtimeError('Bad packet header.')
                if repl_len + 12 > len(buf):
                    continue
                data = buf[:repl_len + 12]
                break
            rtt = time.monotonic() - start_time
            sock.close()
            if rtt >= timeout:
                # Try next IP on timeout.
                continue
            # Break out of loop if successful.
            break
        if rtt >= timeout:
            raise RoughtimeError('Timeout while waiting for reply.')
        reply = RoughtimePacket(packet=data)

        return reply, rtt, data

    def query(self, address, port, pubkey, timeout=2, newver=True,
            protocol='udp'):
        '''
        Sends a time query to the server and waits for a reply.

        Args:
            address (str): The server address.
            port (int): The server port.
            pubkey (str): The server's public key in base64 format.
            timeout (float): Time to wait for a reply from the server.
            newver (boolean): True if the server follows the most recent IETF
                    draft specification. Set to false for compatibility with
                    pre-IETF specifications.
            protocol (str): Either 'udp' or 'tcp'.

        Raises:
            RoughtimeError: On any error. The message will describe the
                    specific error that occurred.

        Returns:
            ret (dict): A dictionary with the following members:
                    midp       - midpoint (MIDP) in microseconds,
                    radi       - accuracy (RADI) in microseconds,
                    datetime   - a datetime object representing the returned
                                 midpoint,
                    prettytime - a string representing the returned time.
                    mint       - a datetime object representing the start of
                                 validity for the delegate key.
                    maxt       - a datetime object representing the end of
                                 validity for the delegate key.
                    pathlen    - the length of the Merkle tree path sent in
                                 the server's reply (0 <= pathlen <= 32).
        '''

        if protocol != 'udp' and protocol != 'tcp':
            raise RoughtimeError('Illegal protocol type.')

        pubkey = ed25519.VerifyingKey(pubkey, encoding='base64')

        # Generate nonce.
        blind = os.urandom(64)
        ha = hashlib.sha512()
        if len(self.prev_replies) > 0:
            ha.update(self.prev_replies[-1][2])
        ha.update(blind)
        nonce = ha.digest()

        # Create query packet.
        packet = RoughtimePacket()
        if newver:
            packet.add_tag(RoughtimeTag('VER', RoughtimeTag.uint32_to_bytes(0x80000003)))
        packet.add_tag(RoughtimeTag('NONC', nonce))
        if protocol == 'udp':
            packet.add_padding()
        packet = packet.get_value_bytes(packet_header=newver)

        if protocol == 'udp':
            reply, rtt, data = self.__udp_query(address, port, packet, timeout)
        else:
            reply, rtt, data = self.__tcp_query(address, port, packet, timeout)

        # Get reply tags.
        srep = reply.get_tag('SREP')
        cert = reply.get_tag('CERT')
        if srep == None or cert == None:
            raise RoughtimeError('Missing tag in server reply.')
        dele = cert.get_tag('DELE')
        if dele == None:
            raise RoughtimeError('Missing tag in server reply.')
        nonc = reply.get_tag('NONC')
        if newver:
            if nonc == None:
                raise RoughtimeError('Missing tag in server reply.')
            if nonc.get_value_bytes() != nonce:
                raise RoughtimeError('Bad NONC in server reply.')

        try:
            dsig = cert.get_tag('SIG').get_value_bytes()
            dtai = srep.get_tag('DTAI')
            leap = srep.get_tag('LEAP')
            midp = srep.get_tag('MIDP').to_int()
            radi = srep.get_tag('RADI').to_int()
            root = srep.get_tag('ROOT').get_value_bytes()
            sig = reply.get_tag('SIG').get_value_bytes()
            indx = reply.get_tag('INDX').to_int()
            path = reply.get_tag('PATH').get_value_bytes()
            pubk = dele.get_tag('PUBK').get_value_bytes()
            mint = dele.get_tag('MINT').to_int()
            maxt = dele.get_tag('MAXT').to_int()

        except:
            raise RoughtimeError('Missing tag in server reply or parse error.')

        if dtai != None:
            dtai = dtai.to_int()

        if leap != None:
            leapbytes = leap.get_value_bytes()
            leap = []
            while len(leapbytes) > 0:
                leap.append(struct.unpack('<I', leapbytes[:4])[0] & 0x7fffffff)
                leapbytes = leapbytes[4:]

        # Verify signature of DELE with long term certificate.
        try:
            pubkey.verify(dsig, RoughtimeServer.CERTIFICATE_CONTEXT
                    + dele.get_received())
        except:
            raise RoughtimeError('Verification of long term certificate '
                    + 'signature failed.')

        # Verify that DELE timestamps are consistent with MIDP value.
        if mint > midp or maxt < midp:
            raise RoughtimeError('MIDP outside delegated key validity time.')

        if newver:
            node_size = 32
        else:
            node_size = 64

        # Ensure that Merkle tree is correct and includes nonce.
        curr_hash = hashlib.sha512(b'\x00' + nonce).digest()[:node_size]
        if len(path) % node_size != 0:
            raise RoughtimeError('PATH length not a multiple of %d.' \
                    % node_size)
        pathlen = len(path) // node_size
        if pathlen > 32:
            raise RoughtimeError('Too many paths in Merkle tree.')

        while len(path) > 0:
            if indx & 1 == 0:
                curr_hash = hashlib.sha512(b'\x01' + curr_hash
                        + path[:node_size]).digest()
            else:
                curr_hash = hashlib.sha512(b'\x01' + path[:node_size]
                        + curr_hash).digest()
            curr_hash = curr_hash[:node_size]
            path = path[node_size:]
            indx >>= 1

        if indx != 0:
            raise RoughtimeError('INDX not zero after traversing PATH.')
        if curr_hash != root:
            raise RoughtimeError('Final Merkle tree value not equal to ROOT.')

        # Verify that DELE signature of SREP is valid.
        delekey = ed25519.VerifyingKey(pubk)
        try:
            delekey.verify(sig, RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                    + srep.get_received())
        except:
            raise RoughtimeError('Bad DELE key signature.')

        self.prev_replies.append((nonce, blind, data))
        while len(self.prev_replies) > self.max_history_len:
            self.prev_replies = self.prev_replies[1:]

        # Return results.
        ret = dict()
        ret['midp'] = midp
        ret['radi'] = radi
        ret['datetime'] = RoughtimeClient.midp_to_datetime(midp)
        timestr = ret['datetime'].strftime('%Y-%m-%d %H:%M:%S.%f')
        if radi < 10000:
            ret['prettytime'] = "%s UTC (+/- %.3f ms)" % (timestr, radi / 1E3)
        else:
            ret['prettytime'] = "%s UTC (+/- %.3f  s)" % (timestr, radi / 1E6)
        ret['rtt'] = rtt
        ret['mint'] = RoughtimeClient.midp_to_datetime(mint)
        ret['maxt'] = RoughtimeClient.midp_to_datetime(maxt)
        ret['pathlen'] = pathlen
        if dtai != None:
            ret['dtai'] = dtai
        if leap != None:
            ret['leap'] = leap
        return ret

    def get_previous_replies(self):
        '''
        Returns a list of previous replies recived by the instance.

        Returns:
            prev_replies (list): A list of tuples (bytes, bytes, bytes)
                    containing a nonce, the blind used to generate the nonce,
                    and the data received from the server in the reply. The
                    list is in chronological order.
        '''
        return self.prev_replies

    def verify_replies(self):
        '''
        Verifies replies from servers that have been received by the instance.

        Returns:
            ret (list): A list of pairs containing the indexes of any invalid
                    pairs. An empty list indicates that no replies appear to
                    violate causality.
        '''
        invalid_pairs = []
        for i in range(len(self.prev_replies)):
            packet_i = RoughtimePacket(packet=self.prev_replies[i][2])
            midp_i = RoughtimeClient.midp_to_datetime(\
                    packet_i.get_tag('SREP').get_tag('MIDP').to_int())
            radi_i = datetime.timedelta(microseconds=packet_i.get_tag('SREP')\
                    .get_tag('RADI').to_int())
            for k in range(i + 1, len(self.prev_replies)):
                packet_k = RoughtimePacket(packet=self.prev_replies[k][2])
                midp_k = RoughtimeClient.midp_to_datetime(\
                        packet_k.get_tag('SREP').get_tag('MIDP').to_int())
                radi_k = datetime.timedelta(microseconds=\
                        packet_k.get_tag('SREP').get_tag('RADI').to_int())
                if midp_i - radi_i > midp_k + radi_k:
                    invalid_pairs.append((i, k))
        return invalid_pairs

class RoughtimeTag:
    '''
    Represents a Roughtime tag in a Roughtime message.

    Args:
        key (str): A Roughtime key. Must me less than or equal to four ASCII
                characters. Values shorter than four characters are padded with
                NULL characters.
        value (bytes): The tag's value.
    '''
    def __init__(self, key, value=b''):
        if len(key) > 4:
            raise ValueError
        while len(key) < 4:
            key += '\x00'
        self.key = key
        assert len(value) % 4 == 0
        self.value = value

    def __repr__(self):
        'Generates a string representation of the tag.'
        tag_uint32 = struct.unpack('<I', RoughtimeTag.tag_str_to_uint32(self.key))[0]
        ret = 'Tag: %s (0x%08x)\n' % (self.get_tag_str(), tag_uint32)
        if self.get_value_len() == 4 or self.get_value_len() == 8:
            ret += "Value: %d\n" % self.to_int()
        ret += "Value bytes:\n"
        num = 0
        for b in self.get_value_bytes():
            ret += '%02x' % b
            num += 1
            if num % 16 == 0:
                ret += '\n'
            else:
                ret += ' '
        if ret[-1] == '\n':
            pass
        elif ret[-1] == ' ':
            ret = ret[:-1] + '\n'
        else:
            ret += '\n'
        return ret

    def get_tag_str(self):
        'Returns the tag key string.'
        return self.key

    def get_tag_bytes(self):
        'Returns the tag as an encoded uint32.'
        assert len(self.key) == 4
        return RoughtimeTag.tag_str_to_uint32(self.key)

    def get_value_len(self):
        'Returns the number of bytes in the tag\'s value.'
        return len(self.get_value_bytes())

    def get_value_bytes(self):
        'Returns the bytes representing the tag\'s value.'
        assert len(self.value) % 4 == 0
        return self.value

    def set_value_bytes(self, val):
        assert len(val) % 4 == 0
        self.value = val

    def set_value_uint32(self, val):
        self.value = struct.pack('<I', val)

    def set_value_uint64(self, val):
        self.value = struct.pack('<Q', val)

    def to_int(self):
        '''
        Converts the tag's value to an integer, either uint32 or uint64.

        Raises:
            ValueError: If the value length isn't exactly four or eight bytes.
        '''
        vlen = len(self.get_value_bytes())
        if vlen == 4:
            (val,) = struct.unpack('<I', self.value)
        elif vlen == 8:
            (val,) = struct.unpack('<Q', self.value)
        else:
            raise ValueError
        return val

    @staticmethod
    def tag_str_to_uint32(tag):
        'Converts a tag string to its uint32 representation.'
        return struct.pack('BBBB', ord(tag[0]), ord(tag[1]), ord(tag[2]),
                ord(tag[3]))

    @staticmethod
    def tag_uint32_to_str(tag):
        'Converts a tag uint32 to it\'s string representation.'
        return chr(tag & 0xff) + chr((tag >> 8) & 0xff) \
                + chr((tag >> 16) & 0xff) + chr(tag >> 24)

    @staticmethod
    def uint32_to_bytes(val):
        return struct.pack('<I', val)

    @staticmethod
    def uint64_to_bytes(val):
        return struct.pack('<Q', val)

class RoughtimePacket(RoughtimeTag):
    '''
    Represents a Roughtime packet.

    Args:
        key (str): The tag key value of this packet. Used if it was contained
                in another Roughtime packet.
        packet (bytes): Bytes received from a Roughtime server that should be
                parsed. Set to None to create an empty packet.

    Raises:
        RoughtimeError: On any error. The message will describe the specific
                error that occurred.
    '''
    def __init__(self, key='\x00\x00\x00\x00', packet=None):
        self.tags = []
        self.key = key
        self.packet = None

        # Return if there is no packet to parse.
        if packet == None:
            return

        self.packet = packet

        if len(packet) % 4 != 0:
            raise RoughtimeError('Packet size is not a multiple of four.')

        if RoughtimePacket.unpack_uint64(packet, 0) == 0x4d49544847554f52:
            if len(packet) - 12 != RoughtimePacket.unpack_uint32(packet, 8):
                raise RoughtimeError('Bad packet size.')
            packet = packet[12:]

        num_tags = RoughtimePacket.unpack_uint32(packet, 0)
        headerlen = 8 * num_tags
        if headerlen > len(packet):
            raise RoughtimeError('Bad packet size.')
        # Iterate over the tags.
        for i in range(num_tags):
            # Tag value offset.
            if i == 0:
                offset = headerlen
            else:
                offset = RoughtimePacket.unpack_uint32(packet, i * 4) \
                        + headerlen
            if offset > len(packet):
                raise RoughtimeError('Bad packet size.')

            # Tag value end.
            if i == num_tags - 1:
                end = len(packet)
            else:
                end = RoughtimePacket.unpack_uint32(packet, (i + 1) * 4) \
                        + headerlen
            if end > len(packet):
                raise RoughtimeError('Bad packet size.')

            # Tag key string.
            key = RoughtimeTag.tag_uint32_to_str(
                    RoughtimePacket.unpack_uint32(packet, (num_tags + i) * 4))

            value = packet[offset:end]

            leaf_tags = ['SIG\x00', 'INDX', 'PATH', 'ROOT', 'MIDP', 'RADI',
                    'PAD\x00', 'PAD\xff', 'NONC', 'MINT', 'MAXT', 'PUBK',
                    'VER\x00', 'DTAI', 'DUT1', 'LEAP']
            parent_tags = ['SREP', 'CERT', 'DELE']
            if self.contains_tag(key):
                raise RoughtimeError('Encountered duplicate tag: %s' % key)
            if key in leaf_tags:
                self.add_tag(RoughtimeTag(key, packet[offset:end]))
            elif key in parent_tags:
                # Unpack parent tags recursively.
                self.add_tag(RoughtimePacket(key, packet[offset:end]))
            else:
                raise RoughtimeError('Encountered unknown tag: %s' % key)

    def add_tag(self, tag):
        '''
        Adds a tag to the packet:

        Args:
            tag (RoughtimeTag): the tag to add.

        Raises:
            RoughtimeError: If a tag with the same key already exists in the
                    packet.
        '''
        for t in self.tags:
            if t.get_tag_str() == tag.get_tag_str():
                raise RoughtimeError('Attempted to add two tags with same key '
                        + 'to RoughtimePacket.')
        self.tags.append(tag)
        self.tags.sort(key=lambda x: struct.unpack('<I', x.get_tag_bytes()))

    def contains_tag(self, tag):
        '''
        Checks if the packet contains a tag.

        Args:
            tag (str): The tag to check for.

        Returns:
            boolean
        '''
        if len(tag) > 4:
            raise ValueError
        while len(tag) < 4:
            tag += '\x00'
        for t in self.tags:
            if t.get_tag_str() == tag:
                return True
        return False

    def get_tag(self, tag):
        '''
        Gets a tag from the packet.

        Args:
            tag (str): The tag to get.

        Return:
            RoughtimeTag or None.
        '''
        if len(tag) > 4:
            raise RoughtimeError('Invalid tag key length.')
        while len(tag) < 4:
            tag += '\x00'
        for t in self.tags:
            if t.get_tag_str() == tag:
                return t
        return None

    def get_tags(self):
        'Returns a list of all tag keys in the packet.'
        return [x.get_tag_str() for x in self.tags]

    def get_num_tags(self):
        'Returns the number of keys in the packet.'
        return len(self.tags)

    def get_value_bytes(self, packet_header=False):
        'Returns the raw byte string representing the value of the tag.'
        packet = struct.pack('<I', len(self.tags))
        offset = 0
        for tag in self.tags[:-1]:
            offset += tag.get_value_len()
            packet += struct.pack('<I', offset)
        for tag in self.tags:
            packet += tag.get_tag_bytes()
        for tag in self.tags:
            packet += tag.get_value_bytes()
        assert len(packet) % 4 == 0
        if packet_header:
            packet = struct.pack('<QI', 0x4d49544847554f52, len(packet)) + packet
        return packet

    def get_received(self):
        return self.packet

    def add_padding(self):
        '''
        Adds a padding tag to ensure that the packet is larger than 1024 bytes,
        if necessary. This method should be called before sending a request
        packet to a Roughtime server.
        '''
        packetlen = len(self.get_value_bytes())
        if packetlen >= 1024:
            return
        padlen = 1016 - packetlen
        # Transmit "PAD\xff" instead of "PAD" for compatibility with older
        # servers that do not properly ignore unknown tags in queries.
        self.add_tag(RoughtimeTag('PAD\xff', b'\x00' * padlen))

    @staticmethod
    def unpack_uint32(buf, offset):
        'Utility function for parsing server replies.'
        return struct.unpack('<I', buf[offset:offset + 4])[0]

    @staticmethod
    def unpack_uint64(buf, offset):
        'Utility function for parsing server replies.'
        return struct.unpack('<Q', buf[offset:offset + 8])[0]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Query Roughtime servers '
            'for the current time and print results. This utility can be used '
            'to query either a single Roughtime server specified on the '
            'command line, or a number of servers listed in a JSON file.')

    parser.add_argument('-o', '--oldver', action='store_true',
            help='use pre-IETF protocol by default')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', nargs=3,
            metavar=('address', 'port', 'b64key'),
            help="query a single server")
    group.add_argument('-l', metavar='file',
            help="query servers listed in a JSON file")

    args = parser.parse_args()

    cl = RoughtimeClient()

    # Query a single server.
    if args.s is not None:
        repl = cl.query(args.s[0], int(args.s[1]), args.s[2],
                newver=not args.oldver)
        print('%s (RTT: %.1f ms)' % (repl['prettytime'], repl['rtt'] * 1000))
        if 'dtai' in repl:
            print('TAI - UTC = %ds' % repl['dtai'])
        if 'leap' in repl:
            if len(repl['leap']) == 0:
                print("Leap events: None")
            else:
                print("Leap events: ")
                for l in repl['leap']:
                    print('  ' + datetime.date.fromordinal(678576 + l).isoformat())
        print('Delegate key validity start: %s' %
                repl['mint'].strftime('%Y-%m-%d %H:%M:%S.%f'))
        if repl['maxt'] is None:
            print('Delegate key validity end:   indefinite')
        else:
            print('Delegate key validity end:   %s' %
                    repl['maxt'].strftime('%Y-%m-%d %H:%M:%S.%f'))
        print('Merkle tree path length: %d' % repl['pathlen'])
        sys.exit(0)

    # Query a list of servers in a JSON file.
    with open(args.l) as f:
        serverlist = json.load(f)['servers']
    for server in serverlist:
        proto = server['addresses'][0]['protocol']
        if server['publicKeyType'] != 'ed25519' \
                or (proto != 'udp' and proto != 'tcp'):
            continue
        if not 'newver' in server:
            newver = not args.oldver
        else:
            newver = server['newver']
        addr, port = server['addresses'][0]['address'].split(':')
        if len(server['name']) > 25:
            space = ' '
        else:
            space = ' ' * (25 - len(server['name']))
        try:
            repl = cl.query(addr, int(port), server['publicKey'],
                    newver=newver, protocol=proto)
            print('%s:%s%s (RTT: %6.1f ms)' % (server['name'], space,
                    repl['prettytime'], repl['rtt'] * 1000))
        except Exception as ex:
            print('%s:%sException: %s' % (server['name'], space, ex))
            continue

    verify = cl.verify_replies()
    if len(verify) > 0:
        print('Inconsistent time replies detected!')
    else:
        print('No inconsistent replies detected.')
