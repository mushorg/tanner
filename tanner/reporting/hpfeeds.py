#
# hpfeeds.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

#
# This code is combination of the following source codes:
#
# https://github.com/buffer/thug/blob/master/hpfeeds/hpfeeds.py
# https://github.com/DinoTools/dionaea/blob/master/modules/python/dionaea/hpfeeds.py
#

import logging
import struct
import hashlib
import sys
import socket
import time

logger = logging.getLogger("pyhpfeeds")

BUFSIZ = 16384

OP_ERROR = 0
OP_INFO = 1
OP_AUTH = 2
OP_PUBLISH = 3
OP_SUBSCRIBE = 4

MAXBUF = 1024 ** 2
SIZES = {
    OP_ERROR: 5 + MAXBUF,
    OP_INFO: 5 + 256 + 20,
    OP_AUTH: 5 + 256 + 20,
    OP_PUBLISH: 5 + MAXBUF,
    OP_SUBSCRIBE: 5 + 256 * 2,
}

__all__ = ["new", "FeedException"]


class BadClient(Exception):
    pass


class FeedException(Exception):
    pass


class Disconnect(Exception):
    pass


# packs a string with 1 byte length field
def strpack8(x):
    if isinstance(x, str):
        x = x.encode("latin1")
    return struct.pack("!B", len(x) % 0xFF) + x


# unpacks a string with 1 byte length field
def strunpack8(x):
    lenght = x[0]
    return x[1 : 1 + lenght], x[1 + lenght :]


def msghdr(op, data):
    return struct.pack("!iB", 5 + len(data), op) + data


def msgpublish(ident, chan, data):
    return msghdr(OP_PUBLISH, strpack8(ident) + strpack8(chan) + data.encode("latin1"))


def msgsubscribe(ident, chan):
    if isinstance(chan, str):
        chan = chan.encode("latin1")
    return msghdr(OP_SUBSCRIBE, strpack8(ident) + chan)


def msgauth(rand, ident, secret):
    auth_hash = hashlib.sha1(rand + secret.encode("latin1")).digest()
    return msghdr(OP_AUTH, strpack8(ident) + auth_hash)


class FeedUnpack(object):
    def __init__(self):
        self.buf = bytearray()

    def __iter__(self):
        return self

    def __next__(self):
        return self.unpack()

    def feed(self, data):
        self.buf.extend(data)

    def unpack(self):
        if len(self.buf) < 5:
            raise StopIteration("No message.")

        ml, opcode = struct.unpack("!iB", self.buf[:5])
        if ml > SIZES.get(opcode, MAXBUF):
            raise BadClient("Not respecting MAXBUF.")

        if len(self.buf) < ml:
            raise StopIteration("No message.")

        data = self.buf[5:ml]
        del self.buf[:ml]
        return opcode, data


class HPC(object):
    def __init__(self, host, port, ident, secret, timeout=3, reconnect=False, reconnect_attempts=3, sleepwait=20):
        self.host, self.port = host, port
        self.ident, self.secret = ident, secret
        self.timeout = timeout
        self.reconnect = reconnect
        self.reconnect_attempts = reconnect_attempts
        self.sleepwait = sleepwait
        self.brokername = "unknown"
        self.connected = False
        self.stopped = False
        self.s = None
        self.unpacker = FeedUnpack()

        try:
            self.tryconnect()
        except Exception:
            raise

    def send(self, data):
        try:
            self.s.sendall(data)
        except socket.timeout:
            logger.warn("Timeout while sending - disconnect.")
            raise Disconnect()
        except socket.error as e:
            logger.warn("Socket error: %s", e)
            raise Disconnect()

    def tryconnect(self):
        if not self.connected:
            i = 0
            while i < self.reconnect_attempts:
                i += 1
                try:
                    self.connect()
                    break
                except socket.error as e:
                    logger.warn("Socket error while connecting: {0}".format(e))
                    time.sleep(self.sleepwait)
                except FeedException as e:
                    logger.warn("FeedException while connecting: {0}".format(e))
                    time.sleep(self.sleepwait)
                except Disconnect as e:
                    logger.warn("Disconnect while connecting.")
                    time.sleep(self.sleepwait)

            if not self.connected:
                raise Disconnect()

    def close_old(self):
        if self.s:
            try:
                self.s.close()

            except Exception:
                pass

    def connect(self):
        self.close_old()

        logger.info("connecting to %s:%s", self.host, self.port)
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.settimeout(self.timeout)
        try:
            self.s.connect((self.host, self.port))
        except Exception:
            raise FeedException("Could not connect to broker.")
        self.connected = True

        try:
            d = self.s.recv(BUFSIZ)
        except socket.timeout:
            raise FeedException("Connection receive timeout.")

        self.unpacker.feed(d)
        for opcode, data in self.unpacker:
            if opcode == OP_INFO:
                name, rest = strunpack8(data)
                rand = bytes(rest)

                logger.debug("info message name: %s, rand: %s", name, repr(rand))
                self.brokername = name

                self.s.send(msgauth(rand, self.ident, self.secret))
                break
            else:
                raise FeedException("Expected info message at this point.")

        self.s.settimeout(None)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        if sys.platform in ("linux2",):
            self.s.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)

    def publish(self, chaninfo, data):
        if type(chaninfo) == str:
            chaninfo = [chaninfo]
        for c in chaninfo:
            try:
                self.send(msgpublish(self.ident, c, data))
            except Disconnect:
                logger.info("Disconnected from broker (in publish).")
                if self.reconnect:
                    self.tryconnect()
                else:
                    raise

    def close(self):
        try:
            self.s.close()
        except Exception:
            logger.warn("Socket exception when closing.")


def new(host=None, port=10000, ident=None, secret=None, reconnect=True):
    try:
        return HPC(host, port, ident, secret, reconnect)
    except Exception:
        raise
