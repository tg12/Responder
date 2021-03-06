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



# This file is part of creddump.
#
# creddump is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# creddump is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with creddump.  If not, see <http://www.gnu.org/licenses/>.

"""
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      bdolangavitt@wesleyan.edu
"""

from framework.newobj import Obj, Pointer
from struct import unpack

ROOT_INDEX = 0x20
LH_SIG = unpack("<H", "lh")[0]
LF_SIG = unpack("<H", "lf")[0]
RI_SIG = unpack("<H", "ri")[0]


def get_root(address_space):
    return Obj("_CM_KEY_NODE", ROOT_INDEX, address_space)


def open_key(root, key):
    if key == []:
        return root

    keyname = key.pop(0)
    for s in subkeys(root):
        if s.Name.upper() == keyname.upper():
            return open_key(s, key)
    print "ERR: Couldn't find subkey %s of %s" % (keyname, root.Name)
    return None


def subkeys(key, stable=True):
    if stable:
        k = 0
    else:
        k = 1
    sk = (key.SubKeyLists[k] / ["pointer", ["_CM_KEY_INDEX"]]).value
    sub_list = []
    if (sk.Signature.value == LH_SIG or
            sk.Signature.value == LF_SIG):
        sub_list = sk.List
    elif sk.Signature.value == RI_SIG:
        lfs = []
        for i in range(sk.Count.value):
            off, tp = sk.get_offset(['List', i])
            lfs.append(Pointer("pointer", sk.address + off, sk.space,
                               ["_CM_KEY_INDEX"]))
        for lf in lfs:
            sub_list += lf.List

    for s in sub_list:
        if s.is_valid() and s.Signature.value == 27502:
            yield s.value


def values(key):
    for v in key.ValueList.List:
        yield v.value


def walk(root):
    for k in subkeys(root):
        yield k
        for j in walk(k):
            yield j
