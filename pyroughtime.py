#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# pyroughtime
# Copyright (C) 2019-2025 Marcus Dansarie <marcus@dansarie.se>
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
import datetime
import json
import secrets
import socket
import struct
import sys
import threading
import time

from base64 import b64decode, b64encode
from typing import Literal, Optional

from Cryptodome.Hash import SHA512
from Cryptodome.Signature import eddsa


class RoughtimeError(Exception):
    'Represents an error that has occured in the Roughtime client.'
    def __init__(self, message: str) -> None:
        super(RoughtimeError, self).__init__(message)


class RoughtimeResult:
    '''
    Represents the result of a Roughtime time request. Use the various methods
    to access information about the request.

    Args:
                 publ (str): the public key used to verify the server's
                    response, as a base-64 encoded string.
                 nonce (str): the nonce sent in the request, as a
                    base64-encoded nonce string.
                 blind (str): the blind used to generate the nonce for the
                    request from a previous response, as a base64-encoded
                    string.
                 request_data (bytes): the request packet sent to the server.
                 response_data (bytes): the response packet received from the
                    server.
                 midp (int): the midpoint timestamp returned by the server, in
                    seconds.
                 radi (int): the radius returned by the server, in seconds.
                 request_time (int): the time at which the request was sent, in
                    nanoseconds. The time must be on the monotonic timescale
                    used by time.monotonic_ns.
                 response_time (int): the time at which the response was
                    received, in nanoseconds. The time must be on the monotonic
                    timescale used by time.monotonic_ns.
                 mint (int): the minimum midpoint time at which the provided
                    certificate may be used to sign responses.
                 maxt (int): the maximum midpoint time at which the provided
                    certificate may be used to sign responses.
                 pathlen (int): the length of the Merkle three path sent in the
                    server's reply.
                 ver (int): the server's reported version.
    '''

    def __init__(self,
                 publ: str,
                 nonce: str,
                 blind: str,
                 request_data: bytes,
                 response_data: bytes,
                 midp: int,
                 radi: int,
                 request_time: int,
                 response_time: int,
                 mint: int,
                 maxt: int,
                 pathlen: int,
                 ver: int,
                 vers: list[int]) -> None:
        self._publ = publ
        self._nonce = nonce
        self._blind = blind
        self._reqdata = request_data
        self._resdata = response_data
        self._midp = midp
        self._radi = radi
        self._request_time = request_time
        self._response_time = response_time
        self._mint = mint
        self._maxt = maxt
        self._pathlen = pathlen
        self._ver = ver
        self._vers = vers

    def __str__(self) -> str:
        '''
        Returns:
            A string representation of the returned time and radius that can be
            shown to a user. Currently, this method returns the output of the
            prettytime method.
        '''
        return self.prettytime()

    def public_key(self) -> str:
        '''
        Returns:
            The public key used to validate the query result, as a
            base64-encoded string.
        '''
        return self._publ

    def nonce(self) -> str:
        '''
        Returns:
            The nonce sent in the request, as a base64-encoded string.
        '''
        return self._nonce

    def blind(self) -> str:
        '''
        Returns:
            The blind used to generate the nonce for this request from a
            previous response, as a base64-encoded string.
        '''
        return self._blind

    def request_packet(self) -> bytes:
        '''
        Returns:
            The request packet sent to the server in this request.
        '''
        return self._reqdata

    def result_packet(self) -> bytes:
        '''
        Returns:
            The result packet sent from the server in reply the request.
        '''
        return self._resdata

    def prettytime(self) -> str:
        '''
        Returns:
            A nice-looking string representation of the time and radius
            returned by the server in the response. The format is of the form
            2000-01-01 12:34:56 UTC (+/-  1 s).
        '''
        timestr = self.datetime().strftime('%Y-%m-%d %H:%M:%S')
        return '%s UTC (+/- % 2d s)' % (timestr, self.radi())

    def midp(self) -> int:
        '''
        Returns:
            The midpoint timestamp in seconds since the Posix epoch at 00:00:00
            on 1 January 1970, representing the best estimate of time of
            processing of the response in the server.
        '''
        return self._midp

    def radi(self) -> int:
        '''
        Returns:
            The radius returned by the server, indicating guaranteed accuracy
            of the midpoint, in seconds.
        '''
        return self._radi

    def datetime(self) -> datetime.datetime:
        '''
        Returns:
            A datetime object representing the midpoint returned by the server.
        '''
        return RoughtimeClient.timestamp_to_datetime(self.midp())

    def rtt(self) -> float:
        '''
        Returns:
            The round trip time, i.e. the time elapsed between the request was
            sent and the response was received, in seconds.
        '''
        return (self._response_time - self._request_time) * 1E-9

    def mint(self):
        '''
        Returns:
            The minimum timestamp for the delegated key used to sign the
            response, indicating the minimum midpoint time for which the
            certificate may be used to sign responses.
        '''
        return RoughtimeClient.timestamp_to_datetime(self._mint)

    def maxt(self):
        '''
        Returns:
            The maximum timestamp for the delegated key used to sign the
            response, indicating the maximum midpoint time for which the
            certificate may be used to sign responses.
        '''
        return RoughtimeClient.timestamp_to_datetime(self._maxt)

    def pathlen(self) -> int:
        '''
        Returns:
            The length of the Merkle tree path sent in the server's reply.
            Equivalent to the height of the Merkle tree.
        '''
        return self._pathlen

    def ver(self: RoughtimeResult) -> str:
        '''
        Returns:
            A string representing the reply version.
        '''
        return RoughtimeResult._ver_to_str(self._ver)

    def vers(self: RoughtimeResult) -> str:
        '''
        Returns:
            A string representing the server's supported versions.
        '''
        ret = ''
        for v in self._vers:
            if len(ret) != 0:
                ret += ' '
            ret += RoughtimeResult._ver_to_str(v)
        return ret

    @staticmethod
    def _ver_to_str(ver: int) -> str:
        if ver & 0x80000000 != 0:
            return 'draft-%02d' % (ver & 0x7fffffff)
        return str(ver)


class RoughtimeServer:
    '''
    Implements a Roughtime server that provides authenticated time. Instances
    are started with the start method and stopped with the stop method.

    Args:
        publ (str): The server's base64-encoded Ed25519 public key.
        cert (str): A base64-encoded Roughtime CERT packet containing a
                delegated certificate signed with a long-term key. The
                certificate signature must have been made using publ.
        dpriv (str): A base64-encoded Ed25519 private key for the delegated
                certificate.
        radi (int): The time accuracy (RADI) that the server should report.

    Raises:
        RoughtimeError: If cert was not signed with publ or if cert and dpriv
                do not represent a valid Ed25519 certificate pair.
    '''
    CERTIFICATE_CONTEXT = b'RoughTime v1 delegation signature\x00'
    SIGNED_RESPONSE_CONTEXT = b'RoughTime v1 response signature\x00'
    ROUGHTIME_HEADER = 0x4d49544847554f52
    ROUGHTIME_VERSION = 0x8000000c

    def __init__(self, publ: str, cert: str, dpriv: str, radi: int = 3) \
            -> None:
        self._sock = None  # type: Optional[socket.socket]
        self._run = False
        self._thread = None  # type: Optional[threading.Thread]
        cert_bytes = b64decode(cert)
        if len(cert_bytes) != 152:
            raise RoughtimeError('Wrong CERT length.')
        self._cert = RoughtimePacket('CERT', cert_bytes)
        self._dpriv = eddsa.import_private_key(b64decode(dpriv))
        if radi < 1:
            radi = 1
        self._radi = int(radi)

        # Ensure that CERT was signed with publ.
        dele = self._cert.get_tag('DELE')
        sig  = self._cert.get_tag('SIG')
        publ_bytes = b64decode(publ)
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
        if self._run:
            raise RoughtimeError('Server already running.')
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind((ip, port))
            self._sock.settimeout(0.001)
            self._run = True
            self._thread = threading.Thread(
                target=RoughtimeServer._recv_thread,
                args=(self,))
            self._thread.start()
        except Exception as ex:
            self._run = False
            if self._thread is not None:
                self._thread.join()
                self._thread = None
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            raise ex

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
        'Count trailing zeros.'
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
    def _construct_merkle(msgs: list[bytes],
                          prev: Optional[list[list[bytes]]] = None,
                          height: Optional[int] = None) -> list[list[bytes]]:
        '''
        Recursively builds a Merkle tree from a list of request messages.

        Args:
            msgs (list[bytes]): List of messages to include in the Merkle tree.
            prev (list[bytes] | None): The partially built tree. Set to None on
                    first call.
            height (int | None): Remaining height of the Merkle tree. Set to
                    None on first call.

        Returns:
            merkle (list[list[bytes]]): A Merkle tree.
        '''

        # If this is the initial call to the method.
        if prev is None:
            # Hash messages.
            hashes = []
            for m in msgs:
                ha = SHA512.new()
                ha.update(b'\x00' + m)
                hashes.append(ha.digest()[:32])
            # Calculate next power of two and height of tree.
            size = RoughtimeServer._clp2(len(hashes))
            height = RoughtimeServer._ctz(size)
            # Extend nonce list to the next power of two.
            hashes += [secrets.token_bytes(32)
                       for x in range(size - len(hashes))]
            return RoughtimeServer._construct_merkle(hashes, [hashes], height)

        assert height is not None

        if height == 0:
            return prev

        out = []
        for i in range(1 << (height - 1)):
            ha = SHA512.new()
            ha.update(b'\x01' + msgs[i * 2] + msgs[i * 2 + 1])
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
        'Converts a datetime object into a Posix timestamp.'
        return int(dt.timestamp())

    @staticmethod
    def _recv_thread(ref: RoughtimeServer) -> None:
        '''
        Request packet receive thread for the server.

        Args:
            ref (RoughtimeServer): reference to the owning server instance.
        '''
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
            prev = 0
            for n in range(ver.get_value_len() // 4):
                vernum = RoughtimePacket.unpack_uint32(ver_bytes, n * 4)
                if n != 0 and vernum <= prev:
                    print('Version numbers not sorted')
                    break
                if vernum == RoughtimeServer.ROUGHTIME_VERSION:
                    version_ok = True
                    break
                prev = vernum
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

            noncelist = [data]
            merkle = RoughtimeServer._construct_merkle(noncelist)
            path_bytes = RoughtimeServer._construct_merkle_path(merkle, 0)

            # Construct reply.
            reply = RoughtimePacket()
            reply.add_tag(ref._cert)
            reply.add_tag(request.get_tag('NONC'))

            # Single nonce Merkle tree.
            indx = RoughtimeTag('INDX')
            indx.set_value_uint32(0)
            reply.add_tag(indx)
            path = RoughtimeTag('PATH')
            path.set_value_bytes(path_bytes)
            reply.add_tag(path)

            srep = RoughtimePacket('SREP')

            verbytes = RoughtimeTag.uint32_to_bytes(
                RoughtimeServer.ROUGHTIME_VERSION)
            srep.add_tag(RoughtimeTag('VER', verbytes))
            srep.add_tag(RoughtimeTag('VERS', verbytes))

            root = RoughtimeTag('ROOT', merkle[-1][0])
            srep.add_tag(root)

            midp = RoughtimeTag('MIDP')
            midp.set_value_uint64(RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now()))
            srep.add_tag(midp)

            radi = RoughtimeTag('RADI')
            radival = ref._radi
            if radival < 1:
                radival = 1
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
        Generates a long-term Ed25519 key pair.

        Returns:
            priv (str): A base64-encoded Ed25519 private key.
            publ (str): A base64-encoded Ed25519 public key.
        '''
        priv = secrets.token_bytes(32)
        publ = eddsa.import_private_key(priv).public_key() \
                                             .export_key(format='raw')
        return (b64encode(priv).decode('ascii'),
                b64encode(publ).decode('ascii'))

    @staticmethod
    def create_delegated_key(priv: str,
                             mint: Optional[int] = None,
                             maxt: Optional[int] = None) -> tuple[str, str]:
        '''
        Generates a Roughtime delegated key signed by a long-term key.

        Args:
            priv (str): A base64-encoded Ed25519 private key.
            mint (int): Start of the delegated key's validity time in seconds
                since the epoch.
            maxt (int): End of the delegated key's validity time in seconds
                since the epoch.

        Returns:
            cert (str): A base64 encoded Roughtime CERT packet.
            dpriv (str): A base64 encoded Ed25519 private key.
        '''
        if mint is None:
            mint = RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now())
        if maxt is None or maxt <= mint:
            maxt = RoughtimeServer._datetime_to_timestamp(
                datetime.datetime.now() + datetime.timedelta(days=30))
        privkey = eddsa.new(eddsa.import_private_key(b64decode(priv)),
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

        return (b64encode(cert.get_value_bytes()).decode('ascii'),
                b64encode(dpriv).decode('ascii'))

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
        cert, dpriv = RoughtimeServer.create_delegated_key(priv)
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
    def __init__(self, max_history_len: int = 100):
        self._prev_replies = []  # type: list[RoughtimeResult]
        self._max_history_len = max_history_len

    @staticmethod
    def timestamp_to_datetime(ts: int) -> datetime.datetime:
        '''
        Converts a Posix timestamp to a datetime instance. The underlying
        implementation supports is limited to 32-bit integers, resulting in
        dates and times after 2106-02-07 06:28:15 being represented
        incorrectly. The behavior for negative timestamps is unspecified.

        Args:
            ts (int): A Posix timestamp in seconds since the epoch at 00:00:00
            on 1 January 1970.

        Returns:
            A datetime representation of the timestamp.
        '''
        # Underlying implementation is limited to 32 bits.
        if ts > 0xffffffff:
            ts = 0xffffffff
        return datetime.datetime.fromtimestamp(ts, datetime.UTC)

    @staticmethod
    def _udp_query(address: str,
                   port: int,
                   packet: bytes,
                   timeout: int | float) \
            -> tuple[RoughtimePacket, int, int, bytes]:
        '''
        Performs a Roughtime query using the UDP transport protocol.

        Args:
            address (str): the IP address or DNS name of the server to query.
            port (str): UDP port number for the request.
            packet (bytes): the Roughtime request packet to send.
            timeout (int | float): time to wait for response packet before
                failing, in seconds.

        Returns:
            packet (RoughtimePacket): a RoughtimePacket instance, representing
                the parsed response packet.
            request_time (int): request transmit time in nanoseconds, as
                reported by time.monotonic_ns().
            response_time (int): response receive time in nanoseconds, as
                reported by time.monotonic_ns().
            data (bytes): the complete response packet.
        '''
        timeout *= 1000000000
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_DGRAM):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                sock.sendto(packet, (sockaddr[0], sockaddr[1]))
                request_time = time.monotonic_ns()
            except Exception:
                # Try next IP on failure.
                sock.close()
                continue

            # Wait for reply
            while time.monotonic_ns() - request_time < timeout:
                remtime = timeout - (time.monotonic_ns() - request_time)
                sock.settimeout(remtime * 1E-9)
                try:
                    data, repl = sock.recvfrom(1500)
                    receive_time = time.monotonic_ns()
                    repl_addr = repl[0]
                    repl_port = repl[1]
                except socket.timeout:
                    continue
                if repl_addr == sockaddr[0] and repl_port == sockaddr[1]:
                    break
            sock.close()
            if receive_time - request_time >= timeout:
                # Try next IP on timeout.
                continue
            # Break out of loop if successful.
            break
        if receive_time - request_time >= timeout:
            raise RoughtimeError('Timeout while waiting for reply.')
        reply = RoughtimePacket(packet=data, expect_header=True)

        return reply, request_time, receive_time, data

    @staticmethod
    def _tcp_query(address: str,
                   port: int,
                   packet: bytes,
                   timeout: int | float) \
            -> tuple[RoughtimePacket, int, int, bytes]:
        '''
        Performs a Roughtime query using the TCP transport protocol. TCP
        queries are an experimental feature.

        Args:
            address (str): the IP address or DNS name of the server to query.
            port (str): TCP port number for the request.
            packet (bytes): the Roughtime request packet to send.
            timeout (int | float): time to wait for response packet before
                failing, in seconds.

        Returns:
            packet (RoughtimePacket): a RoughtimePacket instance, representing
                the parsed response packet.
            request_time (int): request transmit time in nanoseconds, as
                reported by time.monotonic_ns().
            response_time (int): response receive time in nanoseconds, as
                reported by time.monotonic_ns().
            data (bytes): the complete response packet.
        '''
        for family, type_, proto, canonname, sockaddr in \
                socket.getaddrinfo(address, port, type=socket.SOCK_STREAM):
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                sock.connect((sockaddr[0], sockaddr[1]))
                sock.sendall(packet)
                request_time = time.monotonic_ns()
            except Exception:
                # Try next IP on failure.
                sock.close()
                continue

            # Wait for reply
            buf = bytes()
            response_time = None
            while time.monotonic_ns() - request_time < timeout * 1000000000:
                remtime = timeout - (time.monotonic_ns() - request_time) * 1E-9
                sock.settimeout(remtime)
                try:
                    buf += sock.recv(4096)
                    if response_time is None:
                        response_time = time.monotonic_ns()
                except socket.timeout:
                    continue
                if len(buf) < 12:
                    continue
                (magic, repl_len) = struct.unpack('<QI', buf[:12])
                if magic != RoughtimeServer.ROUGHTIME_HEADER:
                    sock.close()
                    raise RoughtimeError('Bad packet header.')
                if repl_len > 1500:
                    sock.close()
                    raise RoughtimeError('Response packet too large')
                if repl_len + 12 > len(buf):
                    continue
                data = buf[:repl_len + 12]
                break
            sock.close()
            if time.monotonic_ns() - request_time >= timeout * 1000000000:
                # Try next IP on timeout.
                continue
            # Break out of loop if successful.
            break
        if time.monotonic_ns() - request_time >= timeout * 1000000000:
            raise RoughtimeError('Timeout while waiting for reply.')
        reply = RoughtimePacket(packet=data, expect_header=True)
        assert response_time is not None
        return reply, request_time, response_time, data

    def query(self,
              address: str,
              port: int,
              publ: str,
              timeout: float | int = 2,
              protocol: Literal['udp', 'tcp'] = 'udp') -> RoughtimeResult:
        '''
        Sends a time query to the server, waits for a reply, and then verifies
        it.

        Args:
            address (str): The server address.
            port (int): The server port.
            publ (str): The server's public key in base64 format. This is used
                to indicate to request a particular signing key from the server
                and to authenticate the received response.
            timeout (float | int): Maximum time to wait for a reply from the
                server, in seconds.
            protocol ('udp' | 'tcp'): The transport layer protocol to use for
                the request.

        Raises:
            RoughtimeError: On any error. The message will describe the
                    specific error that occurred.

        Returns:
            A RoughtimeResult instance, describing the query result.
        '''

        if protocol != 'udp' and protocol != 'tcp':
            raise RoughtimeError('Illegal protocol type.')

        publ_bytes = b64decode(publ)
        pubkey = eddsa.new(eddsa.import_public_key(publ_bytes), 'rfc8032')

        # Generate nonce.
        blind = secrets.token_bytes(32)
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
            query_fun = self._udp_query
        elif protocol == 'tcp':
            query_fun = self._tcp_query
        else:
            raise ValueError('Bad protocol string.')

        reply, request_time, response_time, result_packet_bytes = \
            query_fun(address, port, request_packet_bytes, timeout)

        # Get reply tags.
        try:
            srep = reply.get_tag('SREP')
            cert = reply.get_tag('CERT')
            if not isinstance(srep, RoughtimePacket) or \
               not isinstance(cert, RoughtimePacket):
                raise Exception()
            dele = cert.get_tag('DELE')
            if not isinstance(dele, RoughtimePacket):
                raise Exception()
            nonc = reply.get_tag('NONC')
            dsig = cert.get_tag('SIG').get_value_bytes()
            midp = srep.get_tag('MIDP').to_int()
            radi = srep.get_tag('RADI').to_int()
            root = srep.get_tag('ROOT').get_value_bytes()
            sig  = reply.get_tag('SIG').get_value_bytes()
            indx = reply.get_tag('INDX').to_int()
            path = reply.get_tag('PATH').get_value_bytes()
            pubk = dele.get_tag('PUBK').get_value_bytes()
            mint = dele.get_tag('MINT').to_int()
            maxt = dele.get_tag('MAXT').to_int()
            ver  = srep.get_tag('VER')
            vers = srep.get_tag('VERS')

        except Exception:
            raise RoughtimeError('Missing tag in server reply or parse error.')
        if nonc.get_value_bytes() != nonce:
            raise RoughtimeError('Bad NONC in server reply.')
        ver_num = ver.to_int()
        ver_list = vers.to_int32_list()

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

        # Ensure that Merkle tree is correct and includes request packet.
        ha.update(b'\x00' + request_packet_bytes)
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
            publ, b64encode(nonce).decode('ascii'),
            b64encode(blind).decode('ascii'), request_packet_bytes,
            result_packet_bytes, midp, radi, request_time, response_time, mint,
            maxt, pathlen, ver_num, ver_list)

        self._prev_replies.append(result)
        while len(self._prev_replies) > self._max_history_len:
            self._prev_replies = self._prev_replies[1:]

        return result

    def get_previous_replies(self) -> list[RoughtimeResult]:
        '''
        Returns a list of previous replies recieved by the instance.

        Returns:
            prev_replies (list[RoughtimeResult]): A list of RoughtimeResult
                    instances. The list is in chronological order.
        '''
        return self._prev_replies

    def get_inconsistent_replies(self) \
            -> list[tuple[RoughtimeResult, RoughtimeResult]]:
        '''
        Goes through the list of replies that have been received by the
        instance so far and verifies that there are no contradicting
        timestamps.

        Returns:
            A list of pairs of RoughtimeResult instances with inconsistent
            times. An empty list indicates that no replies appear to violate
            causality.
        '''
        invalid_pairs = []
        for i in range(len(self._prev_replies)):
            reply_i = self._prev_replies[i]
            packet_i = RoughtimePacket(packet=reply_i.result_packet())
            srep_i = packet_i.get_tag('SREP')
            assert isinstance(srep_i, RoughtimePacket)
            midp_i = RoughtimeClient.timestamp_to_datetime(
                srep_i.get_tag('MIDP').to_int())
            radi_i = datetime.timedelta(
                microseconds=srep_i.get_tag('RADI').to_int())
            for k in range(i + 1, len(self._prev_replies)):
                reply_k = self._prev_replies[k]
                packet_k = RoughtimePacket(packet=reply_k.result_packet())
                srep_k = packet_k.get_tag('SREP')
                assert isinstance(srep_k, RoughtimePacket)
                midp_k = RoughtimeClient.timestamp_to_datetime(
                    srep_k.get_tag('MIDP').to_int())
                radi_k = datetime.timedelta(
                    microseconds=srep_k.get_tag('RADI').to_int())
                if midp_i - radi_i > midp_k + radi_k:
                    invalid_pairs.append((reply_i, reply_k))
        return invalid_pairs

    def verify_replies(self) -> bool:
        '''
        Goes through the list of replies that have been received by the
        instance so far and verifies that there are no contradicting
        timestamps. Call get_inconsistent_replies for a list of pairs that
        violate causality.

        Returns:
            True if the replies are consistent, False if there are
            inconsistencies.
        '''
        return not self.get_inconsistent_replies()

    def get_malfeasance_report(self) -> str:
        '''
        Creates a Roughtime malfaesance report in JSON format. The report is
        created from the list of previous replies held by this instance. Note
        that this method will always generate a report, regardless of if there
        exist inconsistent replies or not. To check if there are inconsistent
        replies, use the verify_replies method.

        Returns:
            A Roughtime malfaesance report in JSON format.
        '''
        responses = []
        first = True
        for r in self._prev_replies:
            response = {
                'nonce': r.nonce(),
                'publicKey': r.public_key(),
                'response': b64encode(r.result_packet()).decode('ascii')
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
    def __init__(self, key: str, value: bytes = b'') -> None:
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
        '''
        Returns:
            The tag key string.
        '''
        return self._key

    def get_tag_bytes(self) -> bytes:
        '''
        Returns:
            The tag as an encoded uint32.
        '''
        assert len(self._key) == 4
        return RoughtimeTag.tag_str_to_uint32(self._key)

    def get_value_len(self) -> int:
        '''
        Returns:
            The number of bytes in the tag's value.
        '''
        return len(self.get_value_bytes())

    def get_value_bytes(self) -> bytes:
        '''
        Returns:
            The bytes representing the tag's value.
        '''
        assert len(self._value) % 4 == 0
        return self._value

    def set_value_bytes(self, val: bytes) -> None:
        '''
        Sets the value of the the tag to a byte string.

        Args:
            val (bytes): The new value of the tag. The number of bytes most be
            an even multiple of 4.
        '''
        assert len(val) % 4 == 0
        self._value = val

    def set_value_uint32(self, val: int) -> None:
        '''
        Sets the value of the the tag to a 32-bit unsigned integer value.

        Args:
            val (int): The new value of the tag.
        '''
        self._value = struct.pack('<I', val)

    def set_value_uint64(self, val: int) -> None:
        '''
        Sets the value of the the tag to a 64-bit unsigned integer value.

        Args:
            val (int): The new value of the tag.
        '''
        self._value = struct.pack('<Q', val)

    def to_int(self) -> int:
        '''
        Interprets the tag's value as an integer, either an uint32 or uint64
        and returns it.

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

    def to_int32_list(self) -> list[int]:
        ret = []
        for n in range(0, len(self._value), 4):
            (val,) = struct.unpack('<I', self._value[n:n + 4])
            ret.append(val)
        return ret

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
        '''
        Converts a 32-bit unsigned integer to its Roughtime uint32
        representation.

        Args:
            val (int): a 32-bit unsigned integer.

        Returns:
            A four-byte Roughtime representation of the integer.
        '''
        return struct.pack('<I', val)

    @staticmethod
    def uint64_to_bytes(val: int) -> bytes:
        '''
        Converts a 64-bit unsigned integer to its Roughtime uint64
        representation.

        Args:
            val (int): a 64-bit unsigned integer.

        Returns:
            A eight-byte Roughtime representation of the integer.
        '''
        return struct.pack('<Q', val)


class RoughtimePacket(RoughtimeTag):
    '''
    Represents a Roughtime packet.

    Args:
        key (str): The tag key value of this packet. Set if this packet was the
            value of another Roughtime packet.
        packet (bytes): Bytes received from a Roughtime server that should be
            parsed. Set to None to create an empty packet.
        expect_header (bool): Set to True if the packet is expected to start
            with a Roughtime header and length field. If this argument is set
            to true and packet does not contain a header, an exception will be
            raised.

    Raises:
        RoughtimeError: On any error. The message will describe the specific
                error that occurred.
    '''
    def __init__(self,
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

    def add_tag(self, tag: RoughtimeTag) -> None:
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

    def contains_tag(self, tag: str) -> bool:
        '''
        Checks if the packet contains a tag.

        Args:
            tag (str): The tag to check for.

        Returns:
            boolean

        Raises:
            ValueError: If the tag key provided in the argument is longer than
                four characters.
        '''
        if len(tag) > 4:
            raise ValueError('Invalid tag key length.')
        while len(tag) < 4:
            tag += '\x00'
        for t in self._tags:
            if t.get_tag_str() == tag:
                return True
        return False

    def get_tag(self: RoughtimePacket, tag: str) -> \
            RoughtimeTag | RoughtimePacket:
        '''
        Gets a tag from the packet.

        Args:
            tag (str): The key for the tag to get.

        Return:
            RoughtimeTag or RoughtimePacket

        Raises:
            RoughtimeError: If a tag with the specified key is not present in
                the packet.
            ValueError: If the tag key provided in the argument is longer than
                four characters.
        '''
        if len(tag) > 4:
            raise ValueError('Invalid tag key length.')
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

    def get_value_bytes(self,
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
        'Utility method for parsing server replies.'
        return struct.unpack('<I', buf[offset:offset + 4])[0]

    @staticmethod
    def unpack_uint64(buf: bytes, offset: int) -> int:
        'Utility method for parsing server replies.'
        return struct.unpack('<Q', buf[offset:offset + 8])[0]


def main():
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
        print('Reply version: ' + repl.ver())
        print('Server versions: ' + repl.vers())
        print('Delegated key validity start: %s' %
              repl.mint().strftime('%Y-%m-%d %H:%M:%S'))
        print('Delegated key validity end:   %s' %
              repl.maxt().strftime('%Y-%m-%d %H:%M:%S'))
        print('Merkle tree path length: %d' % repl.pathlen())
        sys.exit(0)
    elif args.t is not None:
        priv = args.t
        publ = b64encode(eddsa.import_private_key(
            b64decode(priv)).public_key()
            .export_key(format='raw')).decode('ascii')
        cert, dpriv = RoughtimeServer.create_delegated_key(priv)
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

    if cl.verify_replies():
        print('No inconsistent replies detected.')
    else:
        print('Inconsistent time replies detected!')
        print('JSON malfeasance report:')
        print(cl.get_malfeasance_report())


if __name__ == '__main__':
    main()
