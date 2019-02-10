#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ed25519
import datetime
import hashlib
import os
import socket
import struct

class RoughtimeError(Exception):
    '''
    Represents an error that has occured in the Roughtime client.
    '''
    def __init__(self, message):
        super(RoughtimeError, self).__init__(message)

class RoughtimeServer:
    '''
    Represents a Roughtime server that provides authenticated time replies.

    Args:
        address (str): The server address.
        port (int): The server port.
        pubkey (str): The server's public key in base64 format.
    '''
    def __init__(self, address, port, pubkey):
        self.address = address
        self.port = port
        self.pubkey = ed25519.VerifyingKey(pubkey, encoding='base64')

    def query(self, prev_reply=None):
        '''
        Sends a time query to the server and waits for a reply.

        Args:
            prev_reply (bytes): A reply previously received from thus or another Roughtime server.
                    It is used to construct a chain of nonces that can be used to create a
                    cryptographic proof of cheating. Just pass the 'reply_data' member of the dict
                    returned by a previous call to this method.

        Raises:
            RoughtimeError: On any error. The message will describe the specific error that
                    occurred.

        Returns:
            ret (dict): A dictionary with the following members:
                    midp       - MIDP in milliseconds,
                    radi       - RADI in milliseconds,
                    prev_reply - the value passed as prev_reply when callin the method,
                    blind      - a random blind value used to create the nonce,
                    nonce      - the nonce sent to the server,
                    reply_data - the raw data returned by the server,
                    prettytime - a string representing the returned time.
        '''

        # Generate nonce.
        if prev_reply == None:
            prev_reply = b''
        blind = os.urandom(64)
        ha = hashlib.sha512()
        ha.update(prev_reply)
        ha.update(blind)
        nonce = ha.digest()

        # Create query packet.
        packet = RoughtimePacket()
        packet.add_tag(RoughtimeTag('NONC', nonce))
        packet.add_padding()

        # Send query and wait for reply.
        ip_addr = socket.gethostbyname(self.address)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(packet.get_value_bytes(), (ip_addr, self.port))
        while True:
            data, (repl_addr, repl_port) = sock.recvfrom(1500)
            if repl_addr == ip_addr and repl_port == self.port:
                break
        reply = RoughtimePacket(data)

        # Get reply tags.
        srep = reply.get_tag('SREP')
        cert = reply.get_tag('CERT')
        if srep == None or cert == None:
            raise RoughtimeError('Missing tag in server reply.')
        dele = cert.get_tag('DELE')
        if dele == None:
            raise RoughtimeError('Missing tag in server reply.')

        try:
            dsig = cert.get_tag('SIG\x00').get_value_bytes()
            midp = srep.get_tag('MIDP').to_int()
            radi = srep.get_tag('RADI').to_int()
            root = srep.get_tag('ROOT').get_value_bytes()
            sig = reply.get_tag('SIG\x00').get_value_bytes()
            indx = reply.get_tag('INDX').to_int()
            path = reply.get_tag('PATH').get_value_bytes()
            pubk = dele.get_tag('PUBK').get_value_bytes()
            mint = dele.get_tag('MINT').to_int()
            maxt = dele.get_tag('MAXT').to_int()
        except:
            raise RoughtimeError('Missing tag in server reply or parse error.')


        CERTIFICATE_CONTEXT = b'RoughTime v1 delegation signature--\x00'
        SIGNED_RESPONSE_CONTEXT = b'RoughTime v1 response signature\x00'

        # Verify signature of DELE with long term certificate.
        try:
            self.pubkey.verify(dsig, CERTIFICATE_CONTEXT + dele.get_value_bytes())
        except:
            raise RoughtimeError('Verification of long term certificate signature failed.')

        # Verify that DELE timestamps are consistent with MIDP value.
        if mint > midp or maxt < midp:
            raise RoughtimeError('MIDP outside delegated key validity time.')

        # Ensure that Merkle tree is correct and includes nonce.
        ha = hashlib.sha512()
        ha.update(b'\x00')
        ha.update(nonce)
        curr_hash = ha.digest()

        if len(path) % 64 != 0:
            raise RoughtimeError('PATH length not a multiple of 64.')
        if len(path) / 64 > 32:
            raise RoughtimeError('Too many paths in Merkle tree.')

        while len(path) > 0:
            ha = hashlib.sha512()
            if indx & 1 == 0:
                ha.update(b'\x01')
                ha.update(curr_hash)
                ha.update(path[:64])
            else:
                ha.update(b'\x01')
                ha.update(path[:64])
                ha.update(curr_hash)
            curr_hash = ha.digest()
            path = path[64:]

        if indx != 0:
            raise RoughtimeError('INDX not zero after traversing PATH.')
        if curr_hash != root:
            raise RoughtimeError('Final Merkle tree value not equal to ROOT.')

        # Verify that DELE signature of SREP is valid.
        delekey = ed25519.VerifyingKey(pubk)
        try:
            delekey.verify(sig, SIGNED_RESPONSE_CONTEXT + srep.get_value_bytes())
        except:
            raise RoughtimeError('Bad DELE key signature.')

        # Return results.
        ret = dict()
        ret['midp'] = midp
        ret['radi'] = radi
        ret['prev_reply'] = prev_reply
        ret['blind'] = blind
        ret['nonce'] = nonce
        ret['reply_data'] = data
        ret['prettytime'] = datetime.datetime.utcfromtimestamp(midp / 1E6) \
            .strftime('%Y-%m-%d %H:%M:%S.%f')
        return ret

    @staticmethod
    def verify_replies(replies):
        '''
        Verifies replies from servers returned by this class.

        Args:
            replies (list): A list of replies returned by query, in chronological order.

        Returns:
            ret (list): A list of invalid pairs. An empty list indicates that no replies appear to
                    violate causality.
        '''
        invalid_pairs = []
        for i in range(len(replies)):
            for k in range(i + 1, len(replies)):
                t1 = replies[i]['midp'] - replies[i]['radi']
                t2 = replies[k]['midp'] + replies[k]['radi']
                if t1 > t2:
                    invalid_pairs.append((i, k))
        return invalid_pairs



class RoughtimeTag:
    '''
    Represents a Roughtime tag in a Roughtime message.

    Args:
        key (str): A Roughtime key. Must me less than or equal to four ASCII characters.
        value (bytes): The value corresponding to the key.
    '''
    def __init__(self, key, value):
        if len(key) > 4:
            raise ValueError
        while len(key) < 4:
            key += '\x00'
        self.key = key
        assert len(value) % 4 == 0
        self.value = value

    def get_tag_str(self):
        'Returns the tag key string.'
        return self.key

    def get_tag_bytes(self):
        'Returns the tag as an encoded uint32.'
        assert len(self.key) == 4
        return RoughtimeTag.tag_str_to_uint32(self.key)

    def get_value_len(self):
        '''
        Returns the number of bytes in the tag's value.
        '''
        return len(self.get_value_bytes())

    def get_value_bytes(self):
        'Returns the bytes representing the tag\'s value.'
        assert len(self.value) % 4 == 0
        return self.value

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
        return struct.pack('BBBB', ord(tag[0]), ord(tag[1]), ord(tag[2]), ord(tag[3]))

    @staticmethod
    def tag_uint32_to_str(tag):
        'Converts a tag uint32 to it\'s string representation.'
        return chr(tag & 0xff) + chr((tag >> 8) & 0xff) + chr((tag >> 16) & 0xff) + chr(tag >> 24)

class RoughtimePacket(RoughtimeTag):
    '''
    Represents a Roughtime packet.

    Args:
        packet (bytes): Bytes received from a Roughtime server that should be parsed. Set to None
                to create an empty packet.
        key (str): The tag key value of this packet. Used if it was contained in another Roughtime
                packet.

    Raises:
        RoughtimeError: On any error. The message will describe the specific error that
                occurred.
    '''
    def __init__(self, packet=None, key='\x00\x00\x00\x00'):
        self.tags = []
        self.key = key

        # Return if there is no packet to parse.
        if packet == None:
            return

        if len(packet) % 4 != 0:
            raise RoughtimeError('Packet size is not a multiple of four.')

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
                offset = RoughtimePacket.unpack_uint32(packet, i * 4) + headerlen
            if offset > len(packet):
                raise RoughtimeError('Bad packet size.')

            # Tag value end.
            if i == num_tags - 1:
                end = len(packet)
            else:
                end = RoughtimePacket.unpack_uint32(packet, (i + 1) * 4) + headerlen
            if end > len(packet):
                raise RoughtimeError('Bad packet size.')

            # Tag key string.
            key = RoughtimeTag.tag_uint32_to_str(
                    RoughtimePacket.unpack_uint32(packet, (num_tags + i) * 4))

            value = packet[offset:end]

            leaf_tags = ['SIG\x00', 'INDX', 'PATH', 'ROOT', 'MIDP', 'RADI', 'PAD\xff', 'NONC',
                    'MINT', 'MAXT', 'PUBK']
            parent_tags = ['SREP', 'CERT', 'DELE']
            if self.contains_tag(key):
                raise RoughtimeError('Encountered duplicate tag: %s' % key)
            if key in leaf_tags:
                self.add_tag(RoughtimeTag(key, packet[offset:end]))
            elif key in parent_tags:
                # Unpack parent tags recursively.
                self.add_tag(RoughtimePacket(packet[offset:end], key))
            else:
                raise RoughtimeError('Encountered unknown tag: %s' % key)

        # Ensure that the library representation is identical with the received bytes.
        assert packet == self.get_value_bytes()

    def add_tag(self, tag):
        '''
        Adds a tag to the packet:

        Args:
            tag (RoughtimeTag): the tag to add.

        Raises:
            RoughtimeError: If a tag with the same key already exists in the packet.
        '''
        for t in self.tags:
            if t.get_tag_str() == tag.get_tag_str():
                raise RoughtimeError('Attempted to add two tags with same key to RoughtimePacket.')
        self.tags.append(tag)

    def contains_tag(self, tag):
        '''
        Checks if the packet contains a tag.

        Args:
            tag (str): The tag to check for.

        Returns:
            boolean
        '''
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

    def get_value_bytes(self):
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
        return packet

    def add_padding(self):
        '''
        Adds a padding tag to ensure that the packet is larger than 1024 bytes, if necessary. This
        method should be called before sending a request packet to a Roughtime server.
        '''
        packetlen = len(self.get_value_bytes())
        if packetlen >= 1024:
            return
        padlen = 1016 - packetlen
        self.add_tag(RoughtimeTag('PAD\xff', b'\x00' * padlen))

    @staticmethod
    def unpack_uint32(buf, offset):
        'Utility function for parsing server replies.'
        (val,) = struct.unpack('<I', buf[offset:offset + 4])
        return val

if __name__ == '__main__':
    google_server = RoughtimeServer('roughtime.sandbox.google.com', 2002,
            'etPaaIxcBMY1oUeGpwvPMCJMwlRVNxv51KK/tktoJTQ=')
    cloudflare_server = RoughtimeServer('roughtime.cloudflare.com', 2002,
            'gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=')
    int08h_server = RoughtimeServer('roughtime.int08h.com', 2002,
            'AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=')

    replies = []
    replies.append(google_server.query())
    print('Google:     %s UTC (+/- %.2fs)' % (replies[-1]['prettytime'], replies[-1]['radi'] / 1E6))
    replies.append(cloudflare_server.query(prev_reply=replies[-1]['reply_data']))
    print('Cloudflare: %s UTC (+/- %.2fs)' % (replies[-1]['prettytime'], replies[-1]['radi'] / 1E6))
    replies.append(int08h_server.query(prev_reply=replies[-1]['reply_data']))
    print('int08h:     %s UTC (+/- %.2fs)' % (replies[-1]['prettytime'], replies[-1]['radi'] / 1E6))
    verify = RoughtimeServer.verify_replies(replies)
    if len(verify) > 0:
        print('Invalid time replies detected!')
    else:
        print('No invalid replies detected.')
