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
import sqlite3


def DumpHashToFile(outfile, data):
    with open(outfile, "w") as dump:
        dump.write(data)


def DbConnect():
    cursor = sqlite3.connect("./Responder.db")
    return cursor


def GetResponderCompleteNTLMv2Hash(cursor):
    res = cursor.execute(
        "SELECT fullhash FROM Responder WHERE type LIKE '%v2%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
    Output = ""
    for row in res.fetchall():
        Output += '{0}'.format(row[0]) + '\n'
    return Output


def GetResponderCompleteNTLMv1Hash(cursor):
    res = cursor.execute(
        "SELECT fullhash FROM Responder WHERE type LIKE '%v1%' AND UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
    Output = ""
    for row in res.fetchall():
        Output += '{0}'.format(row[0]) + '\n'
    return Output


cursor = DbConnect()
print("Dumping NTLMV2 hashes:")
v2 = GetResponderCompleteNTLMv2Hash(cursor)
DumpHashToFile("DumpNTLMv2.txt", v2)
print(v2)
print("\nDumping NTLMv1 hashes:")
v1 = GetResponderCompleteNTLMv1Hash(cursor)
DumpHashToFile("DumpNTLMv1.txt", v1)
print(v1)
