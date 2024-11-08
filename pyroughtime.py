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
from typing import Literal, Optional

from Cryptodome.Hash import SHA512
from Cryptodome.Signature import eddsa


class RoughtimeError(Exception):
    'Represents an error that has occured in the Roughtime client.'
    def __init__(self: RoughtimeError, message: str) -> None:
        super(RoughtimeError, self).__init__(message)


class RoughtimeResult:
    'Represents the result of a Roughtime time request.'
    def __init__(self: RoughtimeResult,
                 publ: str,
                 nonce: str,
                 blind: str,
                 reqdata: bytes,
                 resdata: bytes,
                 midp: int,
                 radi: int,
                 rtt: float,
                 mint: int,
                 maxt: int,
                 pathlen: int,
                 ver: int) -> None:
        self._publ = publ
        self._nonce = nonce
        self._blind = blind
        self._reqdata = reqdata
        self._resdata = resdata
        self._midp = midp
        self._radi = radi
        self._rtt = rtt
        self._mint = mint
        self._maxt = maxt
        self._pathlen = pathlen
        self._ver = ver

    def __str__(self: RoughtimeResult) -> str:
        return self.prettytime()

    def public_key(self: RoughtimeResult) -> str:
        return self._publ

    def nonce(self: RoughtimeResult) -> str:
        return self._nonce

    def blind(self: RoughtimeResult) -> str:
        return self._blind

    def request_packet(self: RoughtimeResult) -> bytes:
        return self._reqdata

    def result_packet(self: RoughtimeResult) -> bytes:
        return self._resdata

    def prettytime(self: RoughtimeResult) -> str:
        timestr = self.datetime().strftime('%Y-%m-%d %H:%M:%S')
        return '%s UTC (+/- % 2d s)' % (timestr, self.radi())

    def midp(self: RoughtimeResult) -> int:
        return self._midp

    def radi(self: RoughtimeResult) -> int:
        return self._radi

    def datetime(self: RoughtimeResult) -> datetime.datetime:
        return RoughtimeClient.timestamp_to_datetime(self.midp())

    def rtt(self: RoughtimeResult) -> float:
        return self._rtt

    def mint(self: RoughtimeResult):
        return RoughtimeClient.timestamp_to_datetime(self._mint)

    def maxt(self: RoughtimeResult):
        return RoughtimeClient.timestamp_to_datetime(self._maxt)

    def pathlen(self: RoughtimeResult) -> int:
        return self._pathlen

    def ver(self: RoughtimeResult) -> str:
        if self._ver & 0x80000000 != 0:
            return 'draft-%02d' % (self._ver & 0x7fffffff)
        return str(self._ver)


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

    def __init__(self: RoughtimeServer, publ: str, cert: str, dpriv: str,
                 radi: int = 3) -> None:
        cert_bytes = base64.b64decode(cert)
        if len(cert_bytes) != 152:
            raise RoughtimeError('Wrong CERT length.')
        self._cert = RoughtimePacket('CERT', cert_bytes)
        self._dpriv = eddsa.import_private_key(base64.b64decode(dpriv))
        if radi < 3:
            radi = 3
        self._radi = int(radi)

        # Ensure that CERT was signed with publ.
        dele = self._cert.get_tag('DELE')
        sig  = self._cert.get_tag('SIG')
        publ_bytes = base64.b64decode(publ)
        pubkey = eddsa.import_public_key(publ_bytes)
        try:
            ver = eddsa.new(pubkey, 'rfc8032')
            ver.verify(RoughtimeServer.CERTIFICATE_CONTEXT
                       + dele.get_value_bytes(),
                       sig.get_value_bytes())
        except Exception:
            raise RoughtimeError('CERT was not signed with publ.')

        # Calculate SRV tag value.
        ha = SHA512.new()
        ha.update(b'\xff')
        ha.update(publ_bytes)
        self._srvval = ha.digest()[:32]

        # Ensure that the CERT and private key are a valid pair.
        assert isinstance(dele, RoughtimePacket)
        dele_pubkey = eddsa.import_public_key(
            dele.get_tag('PUBK').get_value_bytes())
        self._sign = eddsa.new(self._dpriv, 'rfc8032')
        testsign = self._sign.sign(RoughtimeServer.SIGNED_RESPONSE_CONTEXT)
        try:
            ver = eddsa.new(dele_pubkey, 'rfc8032')
            ver.verify(RoughtimeServer.SIGNED_RESPONSE_CONTEXT, testsign)
        except Exception:
            raise RoughtimeError('CERT and dpriv arguments are not a valid '
                                 + 'certificate pair.')

    def start(self, ip: str, port: int) -> None:
        '''
        Starts the Roughtime server.

        Args:
            ip (str): The IP address the server should bind to.
            port (int): The UDP port the server should bind to.
        '''
        self._sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM)  # type: Optional[socket.socket]
        self._sock.bind((ip, port))
        self._sock.settimeout(0.001)
        self._run = True
        self._thread = threading.Thread(
            target=RoughtimeServer._recv_thread,
            args=(self,))  # type: Optional[threading.Thread]
        self._thread.start()

    def stop(self) -> None:
        'Stops the Roughtime server.'
        if not self._run:
            return
        self._run = False
        assert self._thread is not None
        assert self._sock is not None
        self._thread.join()
        self._sock.close()
        self._thread = None
        self._sock = None

    @staticmethod
    def _ctz(v):
        return (v & -v).bit_length() - 1

    @staticmethod
    def _clp2(x: int) -> int:
        'Returns the next power of two.'
        x -= 1
        x |= x >>  1
        x |= x >>  2
        x |= x >>  4
        x |= x >>  8
        x |= x >> 16
        return x + 1

    @staticmethod
    def _construct_merkle(nonces: list[bytes],
                          prev: Optional[list[list[bytes]]] = None,
                          height: Optional[int] = None) -> list[list[bytes]]:
        '''
        Recursively builds a Merkle tree from a list of nonces.

        Args:
            nonces (list[bytes]): List of nonces to include in the Merkle tree.
            prev (list[bytes] | None): The partially built tree. Set to None on
                    first call.
            height: (int | None): Remaining height of the Merkle tree. Set to
                    None on first call.

        Returns:
            merkle (list[list[bytes]]): A Merkle tree.
        '''

        # If this is the initial call to the function.
        if prev is None:
            # Hash nonces.
            hashes = []
            for n in nonces:
                ha = SHA512.new()
                ha.update(b'\x00' + n)
                hashes.append(ha.digest()[:32])
            # Calculate next power of two and height of tree.
            size = RoughtimeServer._clp2(len(hashes))
            height = RoughtimeServer._ctz(size)
            # Extend nonce list to the next power of two.
            hashes += [os.urandom(32) for x in range(size - len(hashes))]
            return RoughtimeServer._construct_merkle(nonces, [hashes], height)

        assert height is not None

        if height == 0:
            return prev

        out = []
        for i in range(1 << (height - 1)):
            ha = SHA512.new()
            ha.update(b'\x01' + nonces[i * 2] + nonces[i * 2 + 1])
            out.append(ha.digest()[:32])
        prev.append(out)
        return RoughtimeServer._construct_merkle(out, prev, height - 1)

    @staticmethod
    def _construct_merkle_path(merkle: list[list[bytes]], index: int) -> bytes:
        'Returns the Merkle tree path for a nonce index.'
        out = b''
        while len(merkle) > 1:
            out += merkle[0][index ^ 1]
            merkle = merkle[1:]
            index >>= 1
        return out

    @staticmethod
    def _datetime_to_timestamp(dt: datetime.datetime) -> int:
        return int(dt.timestamp())

    @staticmethod
    def _recv_thread(ref: RoughtimeServer) -> None:
        assert ref._sock is not None
        while ref._run:
            try:
                data, addr = ref._sock.recvfrom(1500)
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
            if ver.get_value_len() % 4 != 0:
                print('Wrong VER value length: %d' % ver.get_value_len())
                continue
            version_ok = False
            ver_bytes = ver.get_value_bytes()
            for n in range(ver.get_value_len() // 4):
                if RoughtimePacket.unpack_uint32(ver_bytes, n * 4) == \
                        RoughtimeServer.ROUGHTIME_VERSION:
                    version_ok = True
                    break
            if not version_ok:
                print('No matching version in request')
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
                if request_srv != ref._srvval:
                    print('Unknown SRV tag value: %s, expected %s'
                          % (request_srv.hex(), ref._srvval.hex()))
                    continue

            noncelist = [nonc]
            merkle = RoughtimeServer._construct_merkle(noncelist)
            path_bytes = RoughtimeServer._construct_merkle_path(merkle, 0)

            # Construct reply.
            reply = RoughtimePacket()
            reply.add_tag(ref._cert)
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
            midp.set_value_uint64(RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now()))
            srep.add_tag(midp)

            radi = RoughtimeTag('RADI')
            radival = ref._radi
            if radival < 3:
                radival = 3
            radi.set_value_uint32(radival)
            srep.add_tag(radi)
            reply.add_tag(srep)

            sig = RoughtimeTag('SIG', ref._sign.sign(
                RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                + srep.get_value_bytes()))
            reply.add_tag(sig)

            ref._sock.sendto(reply.get_value_bytes(packet_header=True), addr)

    @staticmethod
    def create_key() -> tuple[str, str]:
        '''
        Generates a long-term key pair.

        Returns:
            priv (str): A base64 encoded ed25519 private key.
            publ (str): A base64 encoded ed25519 public key.
        '''
        priv = secrets.token_bytes(32)
        publ = eddsa.import_private_key(priv).public_key() \
                                             .export_key(format='raw')
        return (base64.b64encode(priv).decode('ascii'),
                base64.b64encode(publ).decode('ascii'))

    @staticmethod
    def create_delegate_key(priv: str,
                            mint: Optional[int] = None,
                            maxt: Optional[int] = None) -> tuple[str, str]:
        '''
        Generates a Roughtime delegate key signed by a long-term key.

        Args:
            priv (str): A base64 encoded ed25519 private key.
            mint (int): Start of the delegate key's validity tile in
                    microseconds since the epoch.
            maxt (int): End of the delegate key's validity tile in
                    microseconds since the epoch.

        Returns:
            cert (str): A base64 encoded Roughtime CERT packet.
            dpriv (str): A base64 encoded ed25519 private key.
        '''
        if mint is None:
            mint = RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now())
        if maxt is None or maxt <= mint:
            maxt = RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now() + datetime.timedelta(days=30))
        privkey = eddsa.new(eddsa.import_private_key(base64.b64decode(priv)),
                            'rfc8032')
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

        delesig = privkey.sign(RoughtimeServer.CERTIFICATE_CONTEXT
                               + dele.get_value_bytes())
        sig = RoughtimeTag('SIG', delesig)

        cert = RoughtimePacket('CERT')
        cert.add_tag(dele)
        cert.add_tag(sig)

        return (base64.b64encode(cert.get_value_bytes()).decode('ascii'),
                base64.b64encode(dpriv).decode('ascii'))

    @staticmethod
    def test_server() -> tuple[RoughtimeServer, str]:
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
    def __init__(self: RoughtimeClient, max_history_len=100):
        self._prev_replies = []  # type: list[RoughtimeResult]
        self._max_history_len = max_history_len

    @staticmethod
    def timestamp_to_datetime(ts: int) -> datetime.datetime:
        # Underlying implementation is limited to 32 bits.
        if ts > 0xffffffff:
            ts = 0xffffffff
        return datetime.datetime.fromtimestamp(ts, datetime.UTC)

    @staticmethod
    def _udp_query(address: str,
                   port: int,
                   packet: bytes,
                   timeout: int | float) \
            -> tuple[RoughtimePacket, float, bytes]:
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_DGRAM):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(0.001)
            try:
                sock.sendto(packet, (sockaddr[0], sockaddr[1]))
            except Exception:
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
        reply = RoughtimePacket(packet=data, expect_header=True)

        return reply, rtt, data

    @staticmethod
    def _tcp_query(address: str,
                   port: int,
                   packet: bytes,
                   timeout: int | float) \
            -> tuple[RoughtimePacket, float, bytes]:
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((sockaddr[0], sockaddr[1]))
                sock.sendall(packet)
            except Exception:
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
        reply = RoughtimePacket(packet=data, expect_header=True)

        return reply, rtt, data

    def query(self: RoughtimeClient,
              address: str,
              port: int,
              publ: str,
              timeout: float | int = 2,
              protocol: Literal['udp', 'tcp'] = 'udp') -> RoughtimeResult:
        '''
        Sends a time query to the server and waits for a reply.

        Args:
            address (str): The server address.
            port (int): The server port.
            publ (str): The server's public key in base64 format.
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
                    ver        - a string representing the server's reported
                                 version. Only present if the server sent a
                                 VER tag in the response.
        '''

        if protocol != 'udp' and protocol != 'tcp':
            raise RoughtimeError('Illegal protocol type.')

        publ_bytes = base64.b64decode(publ)
        pubkey = eddsa.new(eddsa.import_public_key(publ_bytes), 'rfc8032')

        # Generate nonce.
        blind = os.urandom(32)
        ha = SHA512.new()
        if len(self._prev_replies) > 0:
            ha.update(self._prev_replies[-1].result_packet())
        ha.update(blind)
        nonce = ha.digest()[:32]

        # Create query packet.
        packet = RoughtimePacket()
        ha = SHA512.new()
        ha.update(b'\xff')
        ha.update(publ_bytes)
        srvhash = ha.digest()[:32]
        packet.add_tag(RoughtimeTag('SRV', srvhash))
        packet.add_tag(RoughtimeTag('VER', RoughtimeTag.uint32_to_bytes(
            RoughtimeServer.ROUGHTIME_VERSION)))
        packet.add_tag(RoughtimeTag('NONC', nonce))
        if protocol == 'udp':
            packet.add_padding()
        request_packet_bytes = packet.get_value_bytes(True)

        if protocol == 'udp':
            reply, rtt, result_packet_bytes = self._udp_query(
                address, port, request_packet_bytes, timeout)
        else:
            reply, rtt, result_packet_bytes = self._tcp_query(
                address, port, request_packet_bytes, timeout)

        # Get reply tags.
        srep = reply.get_tag('SREP')
        cert = reply.get_tag('CERT')
        assert isinstance(srep, RoughtimePacket)
        assert isinstance(cert, RoughtimePacket)
        if srep is None or cert is None:
            raise RoughtimeError('Missing tag in server reply.')
        dele = cert.get_tag('DELE')
        assert isinstance(dele, RoughtimePacket)
        if dele is None:
            raise RoughtimeError('Missing tag in server reply.')
        if not reply.contains_tag('NONC'):
            raise RoughtimeError('Missing tag in server reply.')
        nonc = reply.get_tag('NONC')
        if nonc.get_value_bytes() != nonce:
            raise RoughtimeError('Bad NONC in server reply.')
        ver = reply.get_tag('VER')

        try:
            dsig = cert.get_tag('SIG').get_value_bytes()
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
            if ver is not None:
                ver_num = ver.to_int()

        except Exception:
            raise RoughtimeError('Missing tag in server reply or parse error.')

        # Verify signature of DELE with long term certificate.
        try:
            recvpacket = dele.get_received()
            assert recvpacket is not None
            pubkey.verify(RoughtimeServer.CERTIFICATE_CONTEXT + recvpacket,
                          dsig)
        except Exception:
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
            raise RoughtimeError('PATH length not a multiple of %d.'
                                 % node_size)
        pathlen = len(path) // node_size
        if pathlen > 32:
            raise RoughtimeError('Too long path in Merkle tree.')

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
            recvpacket = srep.get_received()
            assert recvpacket is not None
            delekey.verify(RoughtimeServer.SIGNED_RESPONSE_CONTEXT
                           + recvpacket, sig)
        except Exception:
            raise RoughtimeError('Bad DELE key signature.')

        result = RoughtimeResult(
            publ, base64.b64encode(nonce).decode('ascii'),
            base64.b64encode(blind).decode('ascii'), request_packet_bytes,
            result_packet_bytes, midp, radi, rtt, mint, maxt, pathlen, ver_num)

        self._prev_replies.append(result)
        while len(self._prev_replies) > self._max_history_len:
            self._prev_replies = self._prev_replies[1:]

        return result

    def get_previous_replies(self: RoughtimeClient) -> list[RoughtimeResult]:
        '''
        Returns a list of previous replies recived by the instance.

        Returns:
            prev_replies (list[RoughtimeResult]): A list of RoughtimeResult
                    instances. The list is in chronological order.
        '''
        return self._prev_replies

    def verify_replies(self: RoughtimeClient) -> list[tuple[int, int]]:
        '''
        Verifies replies from servers that have been received by the instance.

        Returns:
            ret (list): A list of pairs containing the indexes of any invalid
                    pairs. An empty list indicates that no replies appear to
                    violate causality.
        '''
        invalid_pairs = []
        for i in range(len(self._prev_replies)):
            packet_i = RoughtimePacket(
                packet=self._prev_replies[i].result_packet())
            srep_i = packet_i.get_tag('SREP')
            assert isinstance(srep_i, RoughtimePacket)
            midp_i = RoughtimeClient.timestamp_to_datetime(
                srep_i.get_tag('MIDP').to_int())
            radi_i = datetime.timedelta(
                microseconds=srep_i.get_tag('RADI').to_int())
            for k in range(i + 1, len(self._prev_replies)):
                packet_k = RoughtimePacket(
                    packet=self._prev_replies[k].result_packet())
                srep_k = packet_k.get_tag('SREP')
                assert isinstance(srep_k, RoughtimePacket)
                midp_k = RoughtimeClient.timestamp_to_datetime(
                    srep_k.get_tag('MIDP').to_int())
                radi_k = datetime.timedelta(
                    microseconds=srep_k.get_tag('RADI').to_int())
                if midp_i - radi_i > midp_k + radi_k:
                    invalid_pairs.append((i, k))
        return invalid_pairs

    def get_malfeasance_report(self: RoughtimeClient) -> str:
        responses = []
        first = True
        for r in self._prev_replies:
            response = {
                'nonce': r.nonce(),
                'publicKey': r.public_key(),
                'response': base64.b64encode(r.result_packet()).decode('ascii')
            }
            if first:
                first = False
            else:
                response['blind'] = r.blind()
            responses.append(response)
        return json.dumps({'responses': responses}, indent=2, sort_keys=True)


class RoughtimeTag:
    '''
    Represents a Roughtime tag in a Roughtime message.

    Args:
        key (str): A Roughtime key. Must me less than or equal to four ASCII
                characters. Values shorter than four characters are padded with
                NULL characters.
        value (bytes): The tag's value.
    '''
    def __init__(self: RoughtimeTag, key: str, value: bytes = b'') -> None:
        if len(key) > 4:
            raise ValueError
        while len(key) < 4:
            key += '\x00'
        self._key = key
        assert len(value) % 4 == 0
        self._value = value

    def __repr__(self) -> str:
        'Generates a string representation of the tag.'
        tag_uint32 = struct.unpack(
            '<I', RoughtimeTag.tag_str_to_uint32(self._key))[0]
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
        return self._key

    def get_tag_bytes(self) -> bytes:
        'Returns the tag as an encoded uint32.'
        assert len(self._key) == 4
        return RoughtimeTag.tag_str_to_uint32(self._key)

    def get_value_len(self) -> int:
        'Returns the number of bytes in the tag\'s value.'
        return len(self.get_value_bytes())

    def get_value_bytes(self) -> bytes:
        'Returns the bytes representing the tag\'s value.'
        assert len(self._value) % 4 == 0
        return self._value

    def set_value_bytes(self: RoughtimeTag, val: bytes) -> None:
        assert len(val) % 4 == 0
        self._value = val

    def set_value_uint32(self: RoughtimeTag, val: int) -> None:
        self._value = struct.pack('<I', val)

    def set_value_uint64(self: RoughtimeTag, val: int) -> None:
        self._value = struct.pack('<Q', val)

    def to_int(self) -> int:
        '''
        Converts the tag's value to an integer, either uint32 or uint64.

        Raises:
            ValueError: If the value length isn't exactly four or eight bytes.
        '''
        vlen = len(self.get_value_bytes())
        if vlen == 4:
            (val,) = struct.unpack('<I', self._value)
        elif vlen == 8:
            (val,) = struct.unpack('<Q', self._value)
        else:
            raise ValueError
        return val

    @staticmethod
    def tag_str_to_uint32(tag: str) -> bytes:
        'Converts a tag string to its uint32 representation.'
        return struct.pack('BBBB',
                           ord(tag[0]), ord(tag[1]), ord(tag[2]), ord(tag[3]))

    @staticmethod
    def tag_uint32_to_str(tag: int) -> str:
        'Converts a tag uint32 to its string representation.'
        return chr(tag & 0xff) + chr((tag >> 8) & 0xff) \
            + chr((tag >> 16) & 0xff) + chr(tag >> 24)

    @staticmethod
    def uint32_to_bytes(val: int) -> bytes:
        return struct.pack('<I', val)

    @staticmethod
    def uint64_to_bytes(val: int) -> bytes:
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
    def __init__(self: RoughtimePacket,
                 key: str = '\x00\x00\x00\x00',
                 packet: Optional[bytes] = None,
                 expect_header: bool = False) -> None:
        self._tags = []  # type: list[RoughtimeTag]
        self._key = key
        self._packet = None

        # Return if there is no packet to parse.
        if packet is None:
            return

        self._packet = packet

        if len(packet) % 4 != 0:
            raise RoughtimeError('Packet size is not a multiple of four.')

        if RoughtimePacket.unpack_uint64(packet, 0) == \
                RoughtimeServer.ROUGHTIME_HEADER:
            if len(packet) - 12 != RoughtimePacket.unpack_uint32(packet, 8):
                raise RoughtimeError('Bad packet size.')
            packet = packet[12:]
        elif expect_header:
            raise RoughtimeError('Missing packet header.')

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

            parent_tags = ['SREP', 'CERT', 'DELE']
            if self.contains_tag(key):
                raise RoughtimeError('Encountered duplicate tag: %s' % key)
            if key not in parent_tags:
                self.add_tag(RoughtimeTag(key, packet[offset:end]))
            else:
                # Unpack parent tags recursively.
                self.add_tag(RoughtimePacket(key, packet[offset:end]))

    def add_tag(self: RoughtimePacket, tag: RoughtimeTag) -> None:
        '''
        Adds a tag to the packet:

        Args:
            tag (RoughtimeTag): the tag to add.

        Raises:
            RoughtimeError: If a tag with the same key already exists in the
                    packet.
        '''
        for t in self._tags:
            if t.get_tag_str() == tag.get_tag_str():
                raise RoughtimeError('Attempted to add two tags with same key '
                                     + 'to RoughtimePacket.')
        self._tags.append(tag)
        self._tags.sort(key=lambda x: struct.unpack('<I', x.get_tag_bytes()))

    def contains_tag(self: RoughtimePacket, tag: str) -> bool:
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
        for t in self._tags:
            if t.get_tag_str() == tag:
                return True
        return False

    def get_tag(self: RoughtimePacket, tag: str) -> RoughtimeTag:
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
        for t in self._tags:
            if t.get_tag_str() == tag:
                return t
        raise RoughtimeError('Tag not found')

    def get_tags(self) -> list[str]:
        'Returns a list of all tag keys in the packet.'
        return [x.get_tag_str() for x in self._tags]

    def get_num_tags(self) -> int:
        'Returns the number of keys in the packet.'
        return len(self._tags)

    def get_value_bytes(self: RoughtimePacket,
                        packet_header: bool = False) -> bytes:
        'Returns the raw byte string representing the value of the tag.'
        packet = struct.pack('<I', len(self._tags))
        offset = 0
        for tag in self._tags[:-1]:
            offset += tag.get_value_len()
            packet += struct.pack('<I', offset)
        for tag in self._tags:
            packet += tag.get_tag_bytes()
        for tag in self._tags:
            packet += tag.get_value_bytes()
        assert len(packet) % 4 == 0
        if packet_header:
            packet = struct.pack('<QI', RoughtimeServer.ROUGHTIME_HEADER,
                                 len(packet)) + packet
        return packet

    def get_received(self) -> Optional[bytes]:
        return self._packet

    def add_padding(self) -> None:
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
    parser = argparse.ArgumentParser(
        description='Query Roughtime servers for the current time and print '
        'results. This utility can be used to query either a single Roughtime '
        'server specified on the command line, or a number of servers listed '
        'in a JSON file.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s',
                       nargs=3,
                       metavar=('address', 'port', 'public_key'),
                       help='query a single server')
    group.add_argument('-l',
                       metavar='file',
                       help='query servers listed in a JSON file')
    group.add_argument('-t',
                       metavar='private_key',
                       help='start a server for testing with the specified '
                       + 'private key')

    args = parser.parse_args()

    cl = RoughtimeClient()

    # Query a single server.
    if args.s is not None:
        repl = cl.query(args.s[0], int(args.s[1]), args.s[2])
        print('%s (RTT: %.1f ms)' % (repl.prettytime(), repl.rtt() * 1000))
        print('Server version: ' + repl.ver())
        print('Delegate key validity start: %s' %
              repl.mint().strftime('%Y-%m-%d %H:%M:%S'))
        print('Delegate key validity end:   %s' %
              repl.maxt().strftime('%Y-%m-%d %H:%M:%S'))
        print('Merkle tree path length: %d' % repl.pathlen())
        sys.exit(0)
    elif args.t is not None:
        priv = args.t
        publ = base64.b64encode(eddsa.import_private_key(
            base64.b64decode(priv)).public_key()
            .export_key(format='raw')).decode('ascii')
        cert, dpriv = RoughtimeServer.create_delegate_key(priv)
        serv = RoughtimeServer(publ, cert, dpriv)
        serv.start('0.0.0.0', 2002)
        print('Roughtime server started on port 2002')
        print('Public key: %s' % publ)
        input('Press enter to stop...')
        serv.stop()
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
            ver = repl.ver()
            print('%s:%s%s RTT: %6.1f ms Version: %s' % (server['name'],
                  space, repl.prettytime(), repl.rtt() * 1000, ver))
        except Exception as ex:
            print('%s:%sException: %s' % (server['name'], space, ex))
            continue

    verify = cl.verify_replies()
    if len(verify) > 0:
        print('Inconsistent time replies detected!')
        print('JSON malfeasance report:')
        print(cl.get_malfeasance_report())
    else:
        print('No inconsistent replies detected.')
