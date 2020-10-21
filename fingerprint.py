'''THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND
NON-INFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR ANYONE
DISTRIBUTING THE SOFTWARE BE LIABLE FOR ANY DAMAGES OR OTHER LIABILITY,
WHETHER IN CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.'''

# Bitcoin Cash (BCH)   qpz32c4lg7x7lnk9jg6qg7s4uavdce89myax5v5nuk
# Ether (ETH) -        0x843d3DEC2A4705BD4f45F674F641cE2D0022c9FB
# Litecoin (LTC) -     Lfk5y4F7KZa9oRxpazETwjQnHszEPvqPvu
# Bitcoin (BTC) -      34L8qWiQyKr8k4TnHDacfjbaSqQASbBtTd

# contact :- github@jamessawyer.co.uk



#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
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
import socket
import struct

from utils import color
from packets import SMBHeader, SMBNego, SMBNegoFingerData, SMBSessionFingerData


def OsNameClientVersion(data):
    try:
        length = struct.unpack('<H', data[43:45])[0]
        pack = tuple(data[47 + length:].split('\x00\x00\x00'))[:2]
        OsVersion, ClientVersion = tuple(
            [e.replace('\x00', '') for e in data[47 + length:].split('\x00\x00\x00')[:2]])
        return OsVersion, ClientVersion
    except BaseException:
        return "Could not fingerprint Os version.", "Could not fingerprint LanManager Client version"


def RunSmbFinger(host):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(host)
        s.settimeout(0.7)

        h = SMBHeader(cmd="\x72", flag1="\x18", flag2="\x53\xc8")
        n = SMBNego(data=SMBNegoFingerData())
        n.calculate()

        Packet = str(h) + str(n)
        Buffer = struct.pack(">i", len(''.join(Packet))) + Packet
        s.send(Buffer)
        data = s.recv(2048)

        if data[8:10] == "\x72\x00":
            Header = SMBHeader(
                cmd="\x73",
                flag1="\x18",
                flag2="\x17\xc8",
                uid="\x00\x00")
            Body = SMBSessionFingerData()
            Body.calculate()

            Packet = str(Header) + str(Body)
            Buffer = struct.pack(">i", len(''.join(Packet))) + Packet

            s.send(Buffer)
            data = s.recv(2048)

        if data[8:10] == "\x73\x16":
            return OsNameClientVersion(data)
    except BaseException:
        print(color("[!] ", 1, 1) + " Fingerprint failed")
        return None
