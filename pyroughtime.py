#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyroughtime
# Copyright (C) 2019-2024 Marcus Dansarie <marcus@dansarie.se>
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

from __future__ import annotations

import argparse
import base64
import datetime
import json
import os
import secrets
import socket
import struct
import sys
import threading
import time

from Cryptodome.Hash import SHA512
from Cryptodome.Signature import eddsa

class RoughtimeError(Exception):
    'Represents an error that has occured in the Roughtime client.'
    def __init__(self, message: str) -> None:
        super(RoughtimeError, self).__init__(message)

class RoughtimeServer:
    '''
    Implements a Roughtime server that provides authenticated time.

    Args:
        publ (str): The server's base64-encoded ed25519 public key.
        cert (str): A base64-encoded Roughtime CERT packet containing a
                delegate certificate signed with a long-term key. The
                certificate signature must have been made using publ.
        dpriv (str): A base64-encoded ed25519 private key for the delegate
                certificate.
        radi (int): The time accuracy (RADI) that the server should report.

    Raises:
        RoughtimeError: If cert was not signed with publ or if cert and dpriv
                do not represent a valid ed25519 certificate pair.
    '''
    CERTIFICATE_CONTEXT = b'RoughTime v1 delegation signature--\x00'
    SIGNED_RESPONSE_CONTEXT = b'RoughTime v1 response signature\x00'
    ROUGHTIME_HEADER = 0x4d49544847554f52
    ROUGHTIME_VERSION = 0x8000000b
    def __init__(self, publ: str, cert: str, dpriv: str, radi: int = 3) \
            -> None:
        publ = base64.b64decode(publ)
        cert = base64.b64decode(cert)
        dpriv = base64.b64decode(dpriv)
        if len(cert) != 152:
            raise RoughtimeError('Wrong CERT length.')
        self.cert = RoughtimePacket('CERT', cert)
        self.dpriv = eddsa.import_private_key(dpriv)
        self.radi = int(radi)

        # Ensure that CERT was signed with publ.
        dele = self.cert.get_tag('DELE')
        sig  = self.cert.get_tag('SIG')
        pubkey = eddsa.import_public_key(publ)
        try:
            ver = eddsa.new(pubkey, 'rfc8032')
            ver.verify(RoughtimeServer.CERTIFICATE_CONTEXT
                       + self.cert.get_tag('DELE').get_value_bytes(),
                       self.cert.get_tag('SIG').get_value_bytes())
        except:
            raise RoughtimeError('CERT was not signed with publ.')

        # Calculate SRV tag value.
        ha = SHA512.new()
        ha.update(b'\xff')
        ha.update(publ)
        self.srvval = ha.digest()[:32]

        # Ensure that the CERT and private key are a valid pair.
        pubkey = eddsa.import_public_key(self.cert.get_tag('DELE') \
                .get_tag('PUBK').get_value_bytes())
        self.sign = eddsa.new(self.dpriv, 'rfc8032')
        testsign = self.sign.sign(RoughtimeServer.SIGNED_RESPONSE_CONTEXT)
        try:
            ver = eddsa.new(pubkey, 'rfc8032')
            ver.verify(RoughtimeServer.SIGNED_RESPONSE_CONTEXT, testsign)
        except:
            raise RoughtimeError('CERT and dpriv arguments are not a valid '
                    + 'certificate pair.')

    def start(self, ip: str, port: int) -> None:
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

    def stop(self) -> None:
        'Stops the Roughtime server.'
        if self.run == False:
            return
        self.run = False
        self.thread.join()
        self.sock.close()
        self.thread = None
        self.sock = None

    @staticmethod
    def __clp2(x: int) -> int:
        'Returns the next power of two.'
        x -= 1
        x |= x >>  1
        x |= x >>  2
        x |= x >>  4
        x |= x >>  8
        x |= x >> 16
        return x + 1

    @staticmethod
    def __construct_merkle(nonces: list[bytes], prev: list[bytes] = None,
                           order: int | None = None) -> list[bytes]:
        'Builds a Merkle tree.'
        # First call:  and calculate order
        if prev == None:
            # Hash nonces.
            hashes = []
            for n in nonces:
                ha = SHA512.new()
                ha.update(b'\x00' + n)
                hashes.append(ha.digest()[:32])
            # Calculate next power of two.
            size = RoughtimeServer.__clp2(len(hashes))
            # Extend nonce list to the next power of two.
            hashes += [os.urandom(32) for x in range(size - len(hashes))]
            # Calculate list order
            order = 0
            while size & 1 == 0:
                order += 1
                size >>= 1
            return RoughtimeServer.__construct_merkle(hashes, [hashes], order)

        if order == 0:
            return prev

        out = []
        for n in range(1 << (order - 1)):
            ha = SHA512.new()
            ha.update(b'\x01' + nonces[n * 2] + nonces[n * 2 + 1])
            out.append(ha.digest()[:32])

        prev.append(out)
        return RoughtimeServer.__construct_merkle(out, prev, order - 1)

    @staticmethod
    def __construct_merkle_path(merkle: list[bytes], index: int) -> bytes:
        'Returns the Merkle tree path for a nonce index.'
        out = b''
        while len(merkle[0]) > 1:
            out += merkle[0][index ^ 1]
            merkle = merkle[1:]
            index >>= 1
        return out

    @staticmethod
    def __datetime_to_timestamp(dt: datetime.datetime) -> int:
        return int(dt.timestamp())

    @staticmethod
    def __recv_thread(ref: RoughtimeServer) -> None:
        while ref.run:
            try:
                data, addr = ref.sock.recvfrom(1500)
            except socket.timeout:
                continue

            # Ignore requests shorter than 1024 bytes.
            if len(data) < 1024:
                print('Bad length.')
                continue

            try:
                request = RoughtimePacket(packet=data, expect_header=True)
            except Exception as ex:
                print(ex)
                print('Bad packet: %s' % str(ex))
                continue

            # Ensure request contains a proper VER tag.
            if not request.contains_tag('VER'):
                print('Request missing VER tag.')
                continue
            if not request.contains_tag('NONC'):
                print('Request missing NONC tag.')
                continue
            ver = request.get_tag('VER')
            if ver.get_value_len() != 4:
                print('Wrong VER value length: %d' % ver.get_value_len())
                continue
            if ver.to_int() != RoughtimeServer.ROUGHTIME_VERSION:
                print('Wrong request version: %d (0x%08x)'
                      % (ver.to_int(), ver.to_int()))
                continue

            # Ensure request contains a proper NONC tag.
            nonc = request.get_tag('NONC').get_value_bytes()
            if len(nonc) != 32:
                print('Wrong NONC value length: %d' % len(nonc))
                continue

            # Check SRV tag, if present.
            if request.contains_tag('SRV'):
                request_srv = request.get_tag('SRV').get_value_bytes()
                if len(request_srv) != 32:
                    print('Bad SRV tag value length: %d' % len(request_srv))
                    continue
                if request_srv != ref.srvval:
                    print('Unknown SRV tag value: %s, expected %s'
                          % (request_srv.hex(), ref.srvval.hex()))
                    continue

            noncelist = [nonc]
            merkle = RoughtimeServer.__construct_merkle(noncelist)
            path_bytes = RoughtimeServer.__construct_merkle_path(merkle, 0)

            # Construct reply.
            reply = RoughtimePacket()
            reply.add_tag(ref.cert)
            reply.add_tag(request.get_tag('NONC'))
            reply.add_tag(RoughtimeTag('VER', RoughtimeTag.uint32_to_bytes(
                    RoughtimeServer.ROUGHTIME_VERSION)))

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
            radival = ref.radi
            if radival < 3:
                radival = 3
            radi.set_value_uint32(radival)
            srep.add_tag(radi)
            reply.add_tag(srep)

            sig = RoughtimeTag('SIG', ref.sign.sign(
                    RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                            + srep.get_value_bytes()))
            reply.add_tag(sig)

            ref.sock.sendto(reply.get_value_bytes(), addr)

    @staticmethod
    def create_key() -> (str, str):
        '''
        Generates a long-term key pair.

        Returns:
            priv (str): A base64 encoded ed25519 private key.
            publ (str): A base64 encoded ed25519 public key.
        '''
        priv = secrets.token_bytes(32)
        publ = eddsa.import_private_key(priv).public_key() \
               .export_key(format='raw')
        return base64.b64encode(priv).decode('ascii'), \
               base64.b64encode(publ).decode('ascii')

    @staticmethod
    def create_delegate_key(priv: str, mint: int = None, maxt: int = None) \
            -> (bytes, bytes):
        '''
        Generates a Roughtime delegate key signed by a long-term key.

        Args:
            priv (str): A base64 encoded ed25519 private key.
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
        priv = base64.b64decode(priv)
        priv = eddsa.new(eddsa.import_private_key(priv), 'rfc8032')
        dpriv = secrets.token_bytes(32)
        dpubl = eddsa.import_private_key(dpriv).public_key() \
                .export_key(format='raw')
        mint_tag = RoughtimeTag('MINT')
        maxt_tag = RoughtimeTag('MAXT')
        mint_tag.set_value_uint64(mint)
        maxt_tag.set_value_uint64(maxt)
        pubk = RoughtimeTag('PUBK')
        pubk.set_value_bytes(dpubl)
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
                base64.b64encode(dpriv)

    @staticmethod
    def test_server() -> RoughtimeServer:
        '''
        Starts a Roughtime server listening on 127.0.0.1, port 2002 for
        testing.

        Returns:
            serv (RoughtimeServer): The server instance.
            publ (str): The server's public long-term key.
        '''
        priv, publ = RoughtimeServer.create_key()
        cert, dpriv = RoughtimeServer.create_delegate_key(priv)
        serv = RoughtimeServer(publ, cert, dpriv)
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
    def midp_to_datetime(midp: int) -> datetime.datetime:
        return datetime.datetime.fromtimestamp(midp, datetime.UTC)

    @staticmethod
    def __udp_query(address: str, port: int, packet: bytes,
                    timeout: int | float) -> (RoughtimePacket, float, bytes):
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
    def __tcp_query(address: str, port: int, packet: bytes,
                    timeout: int | float) -> (RoughtimePacket, float, bytes):
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
                if magic != RoughtimeServer.ROUGHTIME_HEADER:
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

    def query(self, address: str, port: int, pubkey: str,
              timeout: float | int = 2,
              protocol: Literal['udp', 'tcp'] = 'udp') -> dict:
        '''
        Sends a time query to the server and waits for a reply.

        Args:
            address (str): The server address.
            port (int): The server port.
            pubkey (str): The server's public key in base64 format.
            timeout (float): Time to wait for a reply from the server.
            protocol (str): Either 'udp' or 'tcp'.

        Raises:
            RoughtimeError: On any error. The message will describe the
                    specific error that occurred.

        Returns:
            ret (dict): A dictionary with the following members:
                    midp       - midpoint (MIDP) in microseconds.
                    radi       - accuracy (RADI) in microseconds.
                    datetime   - a datetime object representing the returned
                                 midpoint.
                    prettytime - a string representing the returned time.
                    rtt        - a float representing the round trip time in
                                 seconds.
                    mint       - a datetime object representing the start of
                                 validity for the delegate key.
                    maxt       - a datetime object representing the end of
                                 validity for the delegate key.
                    pathlen    - the length of the Merkle tree path sent in
                                 the server's reply (0 <= pathlen <= 32).
                    dtai       - an integer representing the current TAI - UTC
                                 value in seconds.
                    leap       - a list of integers representing the modified
                                 julian dates of leap second events reported
                                 by the server.
                    ver        - a string representing the server's reported
                                 version. Only present if the server sent a
                                 VER tag in the response.
        '''

        if protocol != 'udp' and protocol != 'tcp':
            raise RoughtimeError('Illegal protocol type.')

        pubkey_bytes = base64.b64decode(pubkey)
        pubkey = eddsa.new(eddsa.import_public_key(pubkey_bytes), 'rfc8032')

        # Generate nonce.
        blind = os.urandom(32)
        ha = SHA512.new()
        if len(self.prev_replies) > 0:
            ha.update(self.prev_replies[-1][2])
        ha.update(blind)
        nonce = ha.digest()[:32]

        # Create query packet.
        packet = RoughtimePacket()
        ha = SHA512.new()
        ha.update(b'\xff')
        ha.update(pubkey_bytes)
        srvhash = ha.digest()[:32]
        packet.add_tag(RoughtimeTag('SRV', srvhash))
        packet.add_tag(RoughtimeTag('VER', RoughtimeTag.uint32_to_bytes(0x8000000B)))
        packet.add_tag(RoughtimeTag('NONC', nonce))
        if protocol == 'udp':
            packet.add_padding()
        packet = packet.get_value_bytes(True)

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
        if not reply.contains_tag('NONC'):
            raise RoughtimeError('Missing tag in server reply.')
        nonc = reply.get_tag('NONC')
        if nonc.get_value_bytes() != nonce:
            raise RoughtimeError('Bad NONC in server reply.')
        ver = reply.get_tag('VER')

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
            ver = reply.get_tag('VER')
            if ver != None:
                ver = ver.to_int()

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
            pubkey.verify(RoughtimeServer.CERTIFICATE_CONTEXT
                          + dele.get_received(), dsig)
        except:
            raise RoughtimeError('Verification of long term certificate '
                    + 'signature failed.')

        # Verify that DELE timestamps are consistent with MIDP value.
        if mint > midp or maxt < midp:
            raise RoughtimeError('MIDP outside delegated key validity time.')

        node_size = 32

        ha = SHA512.new()

        # Ensure that Merkle tree is correct and includes nonce.
        ha.update(b'\x00' + nonce)
        curr_hash = ha.digest()[:node_size]
        if len(path) % node_size != 0:
            raise RoughtimeError('PATH length not a multiple of %d.' \
                    % node_size)
        pathlen = len(path) // node_size
        if pathlen > 32:
            raise RoughtimeError('Too many paths in Merkle tree.')

        while len(path) > 0:
            ha = ha.new()
            if indx & 1 == 0:
                ha.update(b'\x01' + curr_hash + path[:node_size])
            else:
                ha.update(b'\x01' + path[:node_size] + curr_hash)
            curr_hash = ha.digest()[:node_size]
            path = path[node_size:]
            indx >>= 1

        if indx != 0:
            raise RoughtimeError('INDX not zero after traversing PATH.')
        if curr_hash != root:
            raise RoughtimeError('Final Merkle tree value not equal to ROOT.')

        # Verify that DELE signature of SREP is valid.
        delekey = eddsa.new(eddsa.import_public_key(pubk), 'rfc8032')
        try:
            delekey.verify(RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                    + srep.get_received(), sig)
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
        timestr = ret['datetime'].strftime('%Y-%m-%d %H:%M:%S')
        ret['prettytime'] = '%s UTC (+/- % 2d s)' % (timestr, radi)
        ret['rtt'] = rtt
        ret['mint'] = RoughtimeClient.midp_to_datetime(mint)
        ret['maxt'] = RoughtimeClient.midp_to_datetime(maxt)
        ret['pathlen'] = pathlen
        if dtai != None:
            ret['dtai'] = dtai
        if leap != None:
            ret['leap'] = leap
        if ver != None:
            if ver & 0x80000000 != 0:
                ret['ver'] = 'draft-%02d' % (ver & 0x7fffffff)
            else:
                ret['ver'] = str(ver)
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
    def __init__(self, key: str, value: bytes = b'') -> None:
        if len(key) > 4:
            raise ValueError
        while len(key) < 4:
            key += '\x00'
        self.key = key
        assert len(value) % 4 == 0
        self.value = value

    def __repr__(self) -> str:
        'Generates a string representation of the tag.'
        tag_uint32 = struct.unpack('<I',
                                   RoughtimeTag.tag_str_to_uint32(self.key))[0]
        ret = 'Tag: %s (0x%08x)\n' % (self.get_tag_str(), tag_uint32)
        if self.get_value_len() == 4 or self.get_value_len() == 8:
            ret += 'Value: %d\n' % self.to_int()
        ret += 'Value bytes:\n'
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

    def get_tag_str(self) -> str:
        'Returns the tag key string.'
        return self.key

    def get_tag_bytes(self) -> bytes:
        'Returns the tag as an encoded uint32.'
        assert len(self.key) == 4
        return RoughtimeTag.tag_str_to_uint32(self.key)

    def get_value_len(self) -> int:
        'Returns the number of bytes in the tag\'s value.'
        return len(self.get_value_bytes())

    def get_value_bytes(self) -> bytes:
        'Returns the bytes representing the tag\'s value.'
        assert len(self.value) % 4 == 0
        return self.value

    def set_value_bytes(self, val: bytes) -> None:
        assert len(val) % 4 == 0
        self.value = val

    def set_value_uint32(self, val: int) -> None:
        self.value = struct.pack('<I', val)

    def set_value_uint64(self, val: int) -> None:
        self.value = struct.pack('<Q', val)

    def to_int(self) -> int:
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
    def tag_str_to_uint32(tag: str) -> bytes:
        'Converts a tag string to its uint32 representation.'
        return struct.pack('BBBB', ord(tag[0]), ord(tag[1]), ord(tag[2]),
                ord(tag[3]))

    @staticmethod
    def tag_uint32_to_str(tag: bytes) -> str:
        'Converts a tag uint32 to it\'s string representation.'
        return chr(tag & 0xff) + chr((tag >> 8) & 0xff) \
                + chr((tag >> 16) & 0xff) + chr(tag >> 24)

    @staticmethod
    def uint32_to_bytes(val: int) -> str:
        return struct.pack('<I', val)

    @staticmethod
    def uint64_to_bytes(val: int) -> str:
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
    def __init__(self, key: str = '\x00\x00\x00\x00', packet: bytes = None,
                 expect_header: bool = False) -> None:
        self.tags = []
        self.key = key
        self.packet = None

        # Return if there is no packet to parse.
        if packet == None:
            return

        self.packet = packet

        if len(packet) % 4 != 0:
            raise RoughtimeError('Packet size is not a multiple of four.')

        if expect_header:
            if RoughtimePacket.unpack_uint64(packet, 0) != \
                    RoughtimeServer.ROUGHTIME_HEADER:
                raise RoughtimeError('Missing packet header.')
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

            parent_tags = ['SREP', 'CERT', 'DELE']
            if self.contains_tag(key):
                raise RoughtimeError('Encountered duplicate tag: %s' % key)
            if key not in parent_tags:
                self.add_tag(RoughtimeTag(key, packet[offset:end]))
            else:
                # Unpack parent tags recursively.
                self.add_tag(RoughtimePacket(key, packet[offset:end]))

    def add_tag(self, tag: RoughtimeTag) -> None:
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

    def contains_tag(self, tag: str) -> bool:
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

    def get_tag(self, tag: str) -> RoughtimeTag | None:
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

    def get_tags(self) -> list[str]:
        'Returns a list of all tag keys in the packet.'
        return [x.get_tag_str() for x in self.tags]

    def get_num_tags(self) -> int:
        'Returns the number of keys in the packet.'
        return len(self.tags)

    def get_value_bytes(self, packet_header: bool = False) -> bytes:
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
            packet = struct.pack('<QI', RoughtimeServer.ROUGHTIME_HEADER,
                                 len(packet)) + packet
        return packet

    def get_received(self) -> bytes:
        return self.packet

    def add_padding(self) -> bytes:
        '''
        Adds a padding tag to ensure that the packet is larger than 1024 bytes,
        if necessary. This method should be called before sending a request
        packet to a Roughtime server.
        '''
        packetlen = len(self.get_value_bytes())
        if packetlen >= 1024:
            return
        padlen = 1016 - packetlen
        self.add_tag(RoughtimeTag('ZZZZ', b'\x00' * padlen))

    @staticmethod
    def unpack_uint32(buf: bytes, offset: int) -> int:
        'Utility function for parsing server replies.'
        return struct.unpack('<I', buf[offset:offset + 4])[0]

    @staticmethod
    def unpack_uint64(buf: bytes, offset: int) -> int:
        'Utility function for parsing server replies.'
        return struct.unpack('<Q', buf[offset:offset + 8])[0]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Query Roughtime servers '
            'for the current time and print results. This utility can be used '
            'to query either a single Roughtime server specified on the '
            'command line, or a number of servers listed in a JSON file.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', nargs=3,
            metavar=('address', 'port', 'b64key'),
            help='query a single server')
    group.add_argument('-l', metavar='file',
            help='query servers listed in a JSON file')

    args = parser.parse_args()

    cl = RoughtimeClient()

    # Query a single server.
    if args.s is not None:
        repl = cl.query(args.s[0], int(args.s[1]), args.s[2])
        print('%s (RTT: %.1f ms)' % (repl['prettytime'], repl['rtt'] * 1000))
        if 'ver' in repl:
            print('Server version: ' + repl['ver'])
        if 'dtai' in repl:
            print('TAI - UTC = %ds' % repl['dtai'])
        if 'leap' in repl:
            if len(repl['leap']) == 0:
                print('Leap events: None')
            else:
                print('Leap events: ')
                for l in repl['leap']:
                    print('  ' + datetime.date.fromordinal(678576 + l).isoformat())
        print('Delegate key validity start: %s' %
                repl['mint'].strftime('%Y-%m-%d %H:%M:%S'))
        if repl['maxt'] is None:
            print('Delegate key validity end:   indefinite')
        else:
            print('Delegate key validity end:   %s' %
                    repl['maxt'].strftime('%Y-%m-%d %H:%M:%S'))
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
        addr, port = server['addresses'][0]['address'].split(':')
        if len(server['name']) > 25:
            space = ' '
        else:
            space = ' ' * (25 - len(server['name']))
        try:
            repl = cl.query(addr, int(port), server['publicKey'],
                            protocol=proto)
            if 'ver' in repl:
                ver = repl['ver']
            else:
                ver = '?'
            print('%s:%s%s RTT: %6.1f ms Version: %s' % (server['name'],
                    space, repl['prettytime'], repl['rtt'] * 1000, ver))
        except Exception as ex:
            print('%s:%sException: %s' % (server['name'], space, ex))
            continue

    verify = cl.verify_replies()
    if len(verify) > 0:
        print('Inconsistent time replies detected!')
    else:
        print('No inconsistent replies detected.')
