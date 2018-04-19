## GSM_UM was a former contribution module of scapy.
It was introduced in [this commit](https://github.com/secdev/scapy/commit/0816058268b2a0e62165bae81a4a1096d8a33dc6#diff-4657724bd0bfa6f4e3950adcfc0f7d12).

However, due to the poor quality of the code (the module is partially auto-generated), to the giant size of the file but also because the file was missing tests, and the author was unreachable, it has been removed from scapy's newer versions.

This page contains the legacy code - an automatically updated and fixed version - of the module before it was removed, but also a copy of its documentation, before the website of the author was shut down.

### Code

```
#!/usr/bin/env python

# This file is part of Scapy
# Scapy is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# any later version.
#
# Scapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Scapy. If not, see <http://www.gnu.org/licenses/>.

# scapy.contrib.description = PPI
# scapy.contrib.status = loads

####################################################################
# This file holds the GSM UM interface implementation for Scapy    #
# author: Laurent Weber <k@0xbadcab1e.lu>                          #
#                                                                  #
# Some examples on how to use this script:                         #
#                      http://0xbadcab1e.lu/scapy_gsm_um-howto.txt #
#                                                                  #
# tested on: scapy-version: 2.2.0 (dev).                           #
# last updated: scapy-version: 2.4.0 (but untested)                #
####################################################################

from __future__ import print_function
import socket

from scapy.compat import chb, raw
from scapy.packet import Packet
from scapy.fields import BitField, XBitField, ByteField, XByteField

# This method is intended to send gsm air packets. It uses a unix domain
# socket. It opens a socket, sends the parameter to the socket and
# closes the socket.
# typeSock determines the type of the socket, can be:
#                  0 for UDP Socket
#                  1 for Unix Domain Socket
#                  2 for TCP


def sendum(x, typeSock=0):
    try:
        if not isinstance(x, bytes):
            x = raw(x)
        if typeSock is 0:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            host = '127.0.0.1'
            port = 28670       # default for openBTS
            s.connect((host, port))
        elif typeSock is 1:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.connect("/tmp/osmoL")
        elif typeSock is 2:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = '127.0.0.1'
            port = 43797
            s.connect((host, port))
        s.send(x)
        s.close()
    except BaseException:
        print("[Error]: There was a problem when trying to transmit data.\
               Please make sure you started the socket server.")

# Known Bugs/Problems:
# If a message uses multiple times the same IE you cannot set the values
# of this IE's if you use the preconfigured packets. You need to build
# the IE's by hand and than assemble them as entire messages.

# The ErrorLength class is a custom exception that gets raised when a
# packet doesn't have the correct size.


class ErrorLength(Exception):
    def __str__(self):
        error = "ERROR: Please make sure you build entire, 8 bit fields."
        return repr(error)
###
# This method computes the length of the actual IE.
# It computes how many "None" fields have to be removed (if any).
# The method returns an integer containing the number of bytes that have to be
# cut off the packet.
# parameter length contains the max length of the IE can be found in
# 0408
# The parameter fields contains the value of the fields (not the default but
# the real, actual value.
# The parameter fields2 contains fields_desc.
# Location contains the location of the length field in the IE. Everything
# after the the length field has to be counted (04.07 11.2.1.1.2)


def _adapt(min_length, max_length, fields, fields2, location=2):
    # find out how much bytes there are between min_length and the location of
    # the length field
    location = min_length - location
    i = len(fields) - 1
    rm = mysum = 0
    while i >= 0:
        if fields[i] is None:
            rm += 1
            try:
                mysum += fields2[i].size
            except AttributeError:  # ByteFields don't have .size
                mysum += 8
        else:
            break
        i -= 1
    if mysum % 8 is 0:
        length = mysum / 8  # Number of bytes we have to delete
        dyn_length = (max_length - min_length - length)
        if dyn_length < 0:
            dyn_length = 0
        if length is max_length:  # Fix for packets that have all values set
            length -= min_length  # to None
        return [length, dyn_length + location]
    else:
        raise ErrorLength()

# Section 10.2/3


class TpPd(Packet):
    """Skip indicator and transaction identifier and Protocol Discriminator"""
    name = "Skip Indicator And Transaction Identifier and Protocol \
Discriminator"
    fields_desc = [
        BitField("ti", 0x0, 4),
        BitField("pd", 0x3, 4)
    ]


class MessageType(Packet):
    """Message Type Section 10.4"""
    name = "Message Type"
    fields_desc = [
        XByteField("mesType", 0x3C)
    ]


##
# Message for Radio Resources management (RR) Section 9.1
###

# Network to MS
def additionalAssignment(MobileAllocation_presence=0,
                         StartingTime_presence=0):
    """ADDITIONAL ASSIGNMENT Section 9.1.1"""
    # Mandatory
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x3B)  # 00111011
    c = ChannelDescription()
    packet = a / b / c
    # Not Mandatory
    if MobileAllocation_presence is 1:
        d = MobileAllocationHdr(ieiMA=0x72, eightBitMA=0x0)
        packet = packet / d
    if StartingTime_presence is 1:
        e = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / e
    return packet


# Network to MS
def assignmentCommand(FrequencyList_presence=0,
                      CellChannelDescription_presence=0,
                      CellChannelDescription_presence1=0,
                      MultislotAllocation_presence=0,
                      ChannelMode_presence=0, ChannelMode_presence1=0,
                      ChannelMode_presence2=0, ChannelMode_presence3=0,
                      ChannelMode_presence4=0, ChannelMode_presence5=0,
                      ChannelMode_presence6=0, ChannelMode_presence7=0,
                      ChannelDescription=0, ChannelMode2_presence=0,
                      MobileAllocation_presence=0, StartingTime_presence=0,
                      FrequencyList_presence1=0,
                      ChannelDescription2_presence=0,
                      ChannelDescription_presence=0,
                      FrequencyChannelSequence_presence=0,
                      MobileAllocation_presence1=0,
                      CipherModeSetting_presence=0,
                      VgcsTargetModeIdentication_presence=0,
                      MultiRateConfiguration_presence=0):
    """ASSIGNMENT COMMAND Section 9.1.2"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2e)  # 101110
    c = ChannelDescription2()
    d = PowerCommand()
    packet = a / b / c / d
    if FrequencyList_presence is 1:
        e = FrequencyListHdr(ieiFL=0x05, eightBitFL=0x0)
        packet = packet / e
    if CellChannelDescription_presence is 1:
        f = CellChannelDescriptionHdr(ieiCCD=0x62, eightBitCCD=0x0)
        packet = packet / f
    if MultislotAllocation_presence is 1:
        g = MultislotAllocationHdr(ieiMSA=0x10, eightBitMSA=0x0)
        packet = packet / g
    if ChannelMode_presence is 1:
        h = ChannelModeHdr(ieiCM=0x63, eightBitCM=0x0)
        packet = packet / h
    if ChannelMode_presence1 is 1:
        i = ChannelModeHdr(ieiCM=0x11, eightBitCM=0x0)
        packet = packet / i
    if ChannelMode_presence2 is 1:
        j = ChannelModeHdr(ieiCM=0x13, eightBitCM=0x0)
        packet = packet / j
    if ChannelMode_presence3 is 1:
        k = ChannelModeHdr(ieiCM=0x14, eightBitCM=0x0)
        packet = packet / k
    if ChannelMode_presence4 is 1:
        l = ChannelModeHdr(ieiCM=0x15, eightBitCM=0x0)
        packet = packet / l
    if ChannelMode_presence5 is 1:
        m = ChannelModeHdr(ieiCM=0x16, eightBitCM=0x0)
        packet = packet / m
    if ChannelMode_presence6 is 1:
        n = ChannelModeHdr(ieiCM=0x17, eightBitCM=0x0)
        packet = packet / n
    if ChannelMode_presence7 is 1:
        o = ChannelModeHdr(ieiCM=0x18, eightBitCM=0x0)
        packet = packet / o
    if ChannelDescription_presence is 1:
        p = ChannelDescriptionHdr(ieiCD=0x64, eightBitCD=0x0)
        packet = packet / p
    if ChannelMode2_presence is 1:
        q = ChannelMode2Hdr(ieiCM2=0x66, eightBitCM2=0x0)
        packet = packet / q
    if MobileAllocation_presence is 1:
        r = MobileAllocationHdr(ieiMA=0x72, eightBitMA=0x0)
        packet = packet / r
    if StartingTime_presence is 1:
        s = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / s
    if FrequencyList_presence1 is 1:
        t = FrequencyListHdr(ieiFL=0x19, eightBitFL=0x0)
        packet = packet / t
    if ChannelDescription2_presence is 1:
        u = ChannelDescription2Hdr(ieiCD2=0x1C, eightBitCD2=0x0)
        packet = packet / u
    if ChannelDescription_presence is 1:
        v = ChannelDescriptionHdr(ieiCD=0x1D, eightBitCD=0x0)
        packet = packet / v
    if FrequencyChannelSequence_presence is 1:
        w = FrequencyChannelSequenceHdr(ieiFCS=0x1E, eightBitFCS=0x0)
        packet = packet / w
    if MobileAllocation_presence1 is 1:
        x = MobileAllocationHdr(ieiMA=0x21, eightBitMA=0x0)
        packet = packet / x
    if CipherModeSetting_presence is 1:
        y = CipherModeSettingHdr(ieiCMS=0x9, eightBitCMS=0x0)
        packet = packet / y
    if VgcsTargetModeIdentication_presence is 1:
        z = VgcsTargetModeIdenticationHdr(ieiVTMI=0x01, eightBitVTMI=0x0)
        packet = packet / z
    if MultiRateConfiguration_presence is 1:
        aa = MultiRateConfigurationHdr(ieiMRC=0x03, eightBitMRC=0x0)
        packet = packet / aa
    return packet


# MS to Network
def assignmentComplete():
    """ASSIGNMENT COMPLETE Section 9.1.3"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x29)  # 00101001
    c = RrCause()
    packet = a / b / c
    return packet


# MS to Network
def assignmentFailure():
    """ASSIGNMENT FAILURE Section 9.1.4"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2F)  # 00101111
    c = RrCause()
    packet = a / b / c
    return packet


# Network to MS
def channelModeModify(VgcsTargetModeIdentication_presence=0,
                      MultiRateConfiguration_presence=0):
    """CHANNEL MODE MODIFY Section 9.1.5"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x8)  # 0001000
    c = ChannelDescription2()
    d = ChannelMode()
    packet = a / b / c / d
    if VgcsTargetModeIdentication is 1:
        e = VgcsTargetModeIdenticationHdr(ieiVTMI=0x01, eightBitVTMI=0x0)
        packet = packet / e
    if MultiRateConfiguration is 1:
        f = MultiRateConfigurationHdr(ieiMRC=0x03, eightBitMRC=0x0)
        packet = packet / f
    return packet


def channelModeModifyAcknowledge():
    """CHANNEL MODE MODIFY ACKNOWLEDGE Section 9.1.6"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x17)  # 00010111
    c = ChannelDescription2()
    d = ChannelMode()
    packet = a / b / c / d
    return packet


# Network to MS
def channelRelease(BaRange_presence=0, GroupChannelDescription_presence=0,
                   GroupCipherKeyNumber_presence=0, GprsResumption_presence=0,
                   BaListPref_presence=0):
    """CHANNEL RELEASE  Section 9.1.7"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0xD)  # 00001101
    c = RrCause()
    packet = a / b / c
    if BaRange_presence is 1:
        d = BaRangeHdr(ieiBR=0x73, eightBitBR=0x0)
        packet = packet / d
    if GroupChannelDescription_presence is 1:
        e = GroupChannelDescriptionHdr(ieiGCD=0x74, eightBitGCD=0x0)
        packet = packet / e
    if GroupCipherKeyNumber_presence is 1:
        f = GroupCipherKeyNumber(ieiGCKN=0x8)
        packet = packet / f
    if GprsResumption_presence is 1:
        g = GprsResumptionHdr(ieiGR=0xC, eightBitGR=0x0)
        packet = packet / g
    if BaListPref_presence is 1:
        h = BaListPrefHdr(ieiBLP=0x75, eightBitBLP=0x0)
        packet = packet / h
    return packet


class ChannelRequest(Packet):
    """Channel request Section 9.1.8"""
    name = "Channel Request"
    fields_desc = [
        ByteField("estCause", 0x0)
    ]


def channelRequest():
    return ChannelRequest()


# Network to MS
def cipheringModeCommand():
    """CIPHERING MODE COMMAND  Section 9.1.9"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x35)  # 00110101
    c = RrCause()
 # d=cipherModeSetting()
 # e=cipherResponse()
 # FIX
    d = CipherModeSettingAndcipherResponse()
    packet = a / b / c / d
    return packet


def cipheringModeComplete(MobileId_presence=0):
    """CIPHERING MODE COMPLETE Section 9.1.10"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x32)  # 00110010
    packet = a / b
    if MobileId_presence is 1:
        c = MobileIdHdr(ieiMI=0x17, eightBitMI=0x0)
        packet = packet / c
    return packet


# Network to MS
def classmarkChange(MobileStationClassmark3_presence=0):
    """CLASSMARK CHANGE Section 9.1.11"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x16)  # 00010110
    c = MobileStationClassmark2()
    packet = a / b / c
    if MobileStationClassmark3_presence is 1:
        e = MobileStationClassmark3(ieiMSC3=0x20)
        packet = packet / e
    return packet


# Network to MS
def classmarkEnquiry():
    """CLASSMARK ENQUIRY Section 9.1.12"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x13)  # 00010011
    packet = a / b
    return packet
# 9.1.12a Spare


# Network to MS
def configurationChangeCommand(ChannelMode_presence=0,
                               ChannelMode_presence1=0,
                               ChannelMode_presence2=0,
                               ChannelMode_presence3=0,
                               ChannelMode_presence4=0,
                               ChannelMode_presence5=0,
                               ChannelMode_presence6=0,
                               ChannelMode_presence7=0):
    """CONFIGURATION CHANGE COMMAND Section 9.1.12b"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x30)  # 00110000
    c = MultislotAllocation()
    packet = a / b / c
    if ChannelMode_presence is 1:
        d = ChannelModeHdr(ieiCM=0x63, eightBitCM=0x0)
        packet = packet / d
    if ChannelMode_presence1 is 1:
        e = ChannelModeHdr(ieiCM=0x11, eightBitCM=0x0)
        packet = packet / e
    if ChannelMode_presence2 is 1:
        f = ChannelModeHdr(ieiCM=0x13, eightBitCM=0x0)
        packet = packet / f
    if ChannelMode_presence3 is 1:
        g = ChannelModeHdr(ieiCM=0x14, eightBitCM=0x0)
        packet = packet / g
    if ChannelMode_presence4 is 1:
        h = ChannelModeHdr(ieiCM=0x15, eightBitCM=0x0)
        packet = packet / h
    if ChannelMode_presence5 is 1:
        i = ChannelModeHdr(ieiCM=0x16, eightBitCM=0x0)
        packet = packet / i
    if ChannelMode_presence6 is 1:
        j = ChannelModeHdr(ieiCM=0x17, eightBitCM=0x0)
        packet = packet / j
    if ChannelMode_presence7 is 1:
        k = ChannelModeHdr(ieiCM=0x18, eightBitCM=0x0)
        packet = packet / k
    return packet


def configurationChangeAcknowledge():
    """CONFIGURATION CHANGE ACKNOWLEDGE Section 9.1.12c"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x31)  # 00110001
    c = MobileId()
    packet = a / b / c
    return packet


def configurationChangeReject():
    """CONFIGURATION CHANGE REJECT Section 9.1.12d"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x33)  # 00110011
    c = RrCause()
    packet = a / b / c
    return packet


# Network to MS
def frequencyRedefinition(CellChannelDescription_presence=0):
    """Frequency redefinition Section 9.1.13"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x14)  # 00010100
    c = ChannelDescription()
    d = MobileAllocation()
    e = StartingTime()
    packet = a / b / c / d / e
    if CellChannelDescription_presence is 1:
        f = CellChannelDescriptionHdr(ieiCCD=0x62, eightBitCCD=0x0)
        packet = packet / f
    return packet


# Network to MS
def pdchAssignmentCommand(ChannelDescription_presence=0,
                          CellChannelDescription_presence=0,
                          MobileAllocation_presence=0,
                          StartingTime_presence=0, FrequencyList_presence=0,
                          ChannelDescription_presence1=0,
                          FrequencyChannelSequence_presence=0,
                          MobileAllocation_presence1=0,
                          PacketChannelDescription_presence=0,
                          DedicatedModeOrTBF_presence=0):
    """PDCH ASSIGNMENT COMMAND Section 9.1.13a"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x23)  # 00100011
    c = ChannelDescription()
    packet = a / b / c
    if ChannelDescription_presence is 1:
        d = ChannelDescriptionHdr(ieiCD=0x62, eightBitCD=0x0)
        packet = packet / d
    if CellChannelDescription_presence is 1:
        e = CellChannelDescriptionHdr(ieiCCD=0x05, eightBitCCD=0x0)
        packet = packet / e
    if MobileAllocation_presence is 1:
        f = MobileAllocationHdr(ieiMA=0x72, eightBitMA=0x0)
        packet = packet / f
    if StartingTime_presence is 1:
        g = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / g
    if FrequencyList_presence is 1:
        h = FrequencyListHdr(ieiFL=0x19, eightBitFL=0x0)
        packet = packet / h
    if ChannelDescription_presence1 is 1:
        i = ChannelDescriptionHdr(ieiCD=0x1C, eightBitCD=0x0)
        packet = packet / i
    if FrequencyChannelSequence_presence is 1:
        j = FrequencyChannelSequenceHdr(ieiFCS=0x1E, eightBitFCS=0x0)
        packet = packet / j
    if MobileAllocation_presence1 is 1:
        k = MobileAllocationHdr(ieiMA=0x21, eightBitMA=0x0)
        packet = packet / k
    if PacketChannelDescription_presence is 1:
        l = PacketChannelDescription(ieiPCD=0x22)
        packet = packet / l
    if DedicatedModeOrTBF_presence is 1:
        m = DedicatedModeOrTBFHdr(ieiDMOT=0x23, eightBitDMOT=0x0)
        packet = packet / m
    return packet


def gprsSuspensionRequest():
    """GPRS SUSPENSION REQUEST Section 9.1.13b"""
    a = TpPd(pd=0x6)
    b = MessageType()
    c = Tlli()
    d = RoutingAreaIdentification()
    e = SuspensionCause()
    packet = a / b / c / d / e
    return packet


class HandoverAccess(Packet):
    name = "Handover Access"  # Section 9.1.14"
    fields_desc = [
        ByteField("handover", None),
    ]


# Network to MS
def handoverCommand(SynchronizationIndication_presence=0,
                    FrequencyShortList_presence=0, FrequencyList_presence=0,
                    CellChannelDescription_presence=0,
                    MultislotAllocation_presence=0,
                    ChannelMode_presence=0, ChannelMode_presence1=0,
                    ChannelMode_presence2=0,
                    ChannelMode_presence3=0, ChannelMode_presence4=0,
                    ChannelMode_presence5=0,
                    ChannelMode_presence6=0, ChannelMode_presence7=0,
                    ChannelDescription_presence1=0, ChannelMode2_presence=0,
                    FrequencyChannelSequence_presence=0,
                    MobileAllocation_presence=0,
                    StartingTime_presence=0, TimeDifference_presence=0,
                    TimingAdvance_presence=0,
                    FrequencyShortList_presence1=0,
                    FrequencyList_presence1=0,
                    ChannelDescription2_presence=0,
                    ChannelDescription_presence2=0,
                    FrequencyChannelSequence_presence1=0,
                    MobileAllocation_presence1=0,
                    CipherModeSetting_presence=0,
                    VgcsTargetModeIdentication_presence=0,
                    MultiRateConfiguration_presence=0):
    """HANDOVER COMMAND Section 9.1.15"""
    name = "Handover Command"
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2b)  # 00101011
    c = CellDescription()
    d = ChannelDescription2()
    e = HandoverReference()
    f = PowerCommandAndAccessType()
    packet = a / b / c / d / e / f
    if SynchronizationIndication_presence is 1:
        g = SynchronizationIndicationHdr(ieiSI=0xD, eightBitSI=0x0)
        packet = packet / g
    if FrequencyShortList_presence is 1:
        h = FrequencyShortListHdr(ieiFSL=0x02)
        packet = packet / h
    if FrequencyList_presence is 1:
        i = FrequencyListHdr(ieiFL=0x05, eightBitFL=0x0)
        packet = packet / i
    if CellChannelDescription_presence is 1:
        j = CellChannelDescriptionHdr(ieiCCD=0x62, eightBitCCD=0x0)
        packet = packet / j
    if MultislotAllocation_presence is 1:
        k = MultislotAllocationHdr(ieiMSA=0x10, eightBitMSA=0x0)
        packet = packet / k
    if ChannelMode_presence is 1:
        l = ChannelModeHdr(ieiCM=0x63, eightBitCM=0x0)
        packet = packet / l
    if ChannelMode_presence1 is 1:
        m = ChannelModeHdr(ieiCM=0x11, eightBitCM=0x0)
        packet = packet / m
    if ChannelMode_presence2 is 1:
        n = ChannelModeHdr(ieiCM=0x13, eightBitCM=0x0)
        packet = packet / n
    if ChannelMode_presence3 is 1:
        o = ChannelModeHdr(ieiCM=0x14, eightBitCM=0x0)
        packet = packet / o
    if ChannelMode_presence4 is 1:
        p = ChannelModeHdr(ieiCM=0x15, eightBitCM=0x0)
        packet = packet / p
    if ChannelMode_presence5 is 1:
        q = ChannelModeHdr(ieiCM=0x16, eightBitCM=0x0)
        packet = packet / q
    if ChannelMode_presence6 is 1:
        r = ChannelModeHdr(ieiCM=0x17, eightBitCM=0x0)
        packet = packet / r
    if ChannelMode_presence7 is 1:
        s = ChannelModeHdr(ieiCM=0x18, eightBitCM=0x0)
        packet = packet / s
    if ChannelDescription_presence1 is 1:
        s1 = ChannelDescriptionHdr(ieiCD=0x64, eightBitCD=0x0)
        packet = packet / s1
    if ChannelMode2_presence is 1:
        t = ChannelMode2Hdr(ieiCM2=0x66, eightBitCM2=0x0)
        packet = packet / t
    if FrequencyChannelSequence_presence is 1:
        u = FrequencyChannelSequenceHdr(ieiFCS=0x69, eightBitFCS=0x0)
        packet = packet / u
    if MobileAllocation_presence is 1:
        v = MobileAllocationHdr(ieiMA=0x72, eightBitMA=0x0)
        packet = packet / v
    if StartingTime_presence is 1:
        w = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / w
    if TimeDifference_presence is 1:
        x = TimeDifferenceHdr(ieiTD=0x7B, eightBitTD=0x0)
        packet = packet / x
    if TimingAdvance_presence is 1:
        y = TimingAdvanceHdr(ieiTA=0x7D, eightBitTA=0x0)
        packet = packet / y
    if FrequencyShortList_presence1 is 1:
        z = FrequencyShortListHdr(ieiFSL=0x12)
        packet = packet / z
    if FrequencyList_presence1 is 1:
        aa = FrequencyListHdr(ieiFL=0x19, eightBitFL=0x0)
        packet = packet / aa
    if ChannelDescription2_presence is 1:
        ab = ChannelDescription2Hdr(ieiCD2=0x1C, eightBitCD2=0x0)
        packet = packet / ab
    if ChannelDescription_presence2 is 1:
        ac = ChannelDescriptionHdr(ieiCD=0x1D, eightBitCD=0x0)
        packet = packet / ac
    if FrequencyChannelSequence_presence1 is 1:
        ad = FrequencyChannelSequenceHdr(ieiFCS=0x1E, eightBitFCS=0x0)
        packet = packet / ad
    if MobileAllocation_presence1 is 1:
        ae = MobileAllocationHdr(ieiMA=0x21, eightBitMA=0x0)
        packet = packet / ae
    if CipherModeSetting_presence is 1:
        af = CipherModeSettingHdr(ieiCMS=0x9, eightBitCMS=0x0)
        packet = packet / af
    if VgcsTargetModeIdentication_presence is 1:
        ag = VgcsTargetModeIdenticationHdr(ieiVTMI=0x01, eightBitVTMI=0x0)
        packet = packet / ag
    if MultiRateConfiguration_presence is 1:
        ah = MultiRateConfigurationHdr(ieiMRC=0x03, eightBitMRC=0x0)
        packet = packet / ah
    return packet


def handoverComplete(MobileTimeDifference_presence=0):
    """HANDOVER COMPLETE Section 9.1.16"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2c)  # 00101100
    c = RrCause()
    packet = a / b / c
    if MobileTimeDifference_presence is 1:
        d = MobileTimeDifferenceHdr(ieiMTD=0x77, eightBitMTD=0x0)
        packet = packet / d
    return packet


def handoverFailure():
    """HANDOVER FAILURE Section 9.1.17"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x28)  # 00101000
    c = RrCause()
    packet = a / b / c
    return packet


# The L2 pseudo length of this message is the sum of lengths of all
# information elements present in the message except
# the IA Rest Octets and L2 Pseudo Length information elements.
# Network to MS
def immediateAssignment(ChannelDescription_presence=0,
                        PacketChannelDescription_presence=0,
                        StartingTime_presence=0):
    """IMMEDIATE ASSIGNMENT Section 9.1.18"""
    a = L2PseudoLength()
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x3F)  # 00111111
    d = PageModeAndDedicatedModeOrTBF()
    packet = a / b / c / d
    if ChannelDescription_presence is 1:
        f = ChannelDescription()
        packet = packet / f
    if PacketChannelDescription_presence is 1:
        g = PacketChannelDescription()
        packet = packet / g
    h = RequestReference()
    i = TimingAdvance()
    j = MobileAllocation()
    packet = packet / h / i / j
    if StartingTime_presence is 1:
        k = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / k
    l = IaRestOctets()
    packet = packet / l
    return packet


# The L2 pseudo length of this message is the sum of lengths of all
# information elements present in the message except
# the IAX Rest Octets and L2 Pseudo Length information elements.

# Network to MS
def immediateAssignmentExtended(StartingTime_presence=0):
    """IMMEDIATE ASSIGNMENT EXTENDED Section 9.1.19"""
    a = L2PseudoLength()
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x39)  # 00111001
    d = PageModeAndSpareHalfOctets()
    f = ChannelDescription()
    g = RequestReference()
    h = TimingAdvance()
    i = MobileAllocation()
    packet = a / b / c / d / f / g / h / i
    if StartingTime_presence is 1:
        j = StartingTimeHdr(ieiST=0x7C, eightBitST=0x0)
        packet = packet / j
    k = IaxRestOctets()
    packet = packet / k
    return packet


# This message has L2 pseudo length 19
# Network to MS
def immediateAssignmentReject():
    """IMMEDIATE ASSIGNMENT REJECT Section 9.1.20"""
    a = L2PseudoLength(l2pLength=0x13)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x3a)  # 00111010
    d = PageModeAndSpareHalfOctets()
    f = RequestReference()
    g = WaitIndication()
    h = RequestReference()
    i = WaitIndication()
    j = RequestReference()
    k = WaitIndication()
    l = RequestReference()
    m = WaitIndication()
    n = IraRestOctets()
    packet = a / b / c / d / f / g / h / i / j / k / l / m / n
    return packet


def measurementReport():
    """MEASUREMENT REPORT Section 9.1.21"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x15)  # 00010101
    c = MeasurementResults()
    packet = a / b / c
    return packet


# len max 20
class NotificationFacch(object):
    """NOTIFICATION/FACCH Section 9.1.21a"""
    name = "Notification/facch"
    fields_desc = [
        BitField("rr", 0x0, 1),
        BitField("msgTyoe", 0x0, 5),
        BitField("layer2Header", 0x0, 2),
        BitField("frChanDes", 0x0, 24)
    ]


# The L2 pseudo length of this message has a value one
# Network to MS
def notificationNch():
    """NOTIFICATION/NCH Section 9.1.21b"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x20)  # 00100000
    d = NtNRestOctets()
    packet = a / b / c / d
    return packet


def notificationResponse():
    """NOTIFICATION RESPONSE Section 9.1.21d"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x26)  # 00100110
    c = MobileStationClassmark2()
    d = MobileId()
    e = DescriptiveGroupOrBroadcastCallReference()
    packet = a / b / c / d / e
    return packet


# Network to MS
def rrCellChangeOrder():
    """RR-CELL CHANGE ORDER  Section  9.1.21e"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x8)  # 00001000
    c = CellDescription()
    d = NcModeAndSpareHalfOctets()
    packet = a / b / c / d
    return packet


# Network to MS
def pagingRequestType1(MobileId_presence=0):
    """PAGING REQUEST TYPE 1 Section 9.1.22"""
 # The L2 pseudo length of this message is the sum of lengths of all
 # information elements present in the message except
 # the P1 Rest Octets and L2 Pseudo Length information elements.
    a = L2PseudoLength()
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x21)  # 00100001
    d = PageModeAndChannelNeeded()
    f = MobileId()
    packet = a / b / c / d / f
    if MobileId_presence is 1:
        g = MobileIdHdr(ieiMI=0x17, eightBitMI=0x0)
        packet = packet / g
    h = P1RestOctets()
    packet = packet / h
    return packet


# The L2 pseudo length of this message is the sum of lengths of all
# information elements present in the message except
# Network to MS
def pagingRequestType2(MobileId_presence=0):
    """PAGING REQUEST TYPE 2  Section 9.1.23"""
    a = L2PseudoLength()
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x22)  # 00100010
    d = PageModeAndChannelNeeded()
    f = MobileId()
    g = MobileId()
    packet = a / b / c / d / f / g
    if MobileId_presence is 1:
        h = MobileIdHdr(ieiMI=0x17, eightBitMI=0x0)
        packet = packet / h
    i = P2RestOctets()
    packet = packet / i
    return packet


# Network to MS
def pagingRequestType3():
    """PAGING REQUEST TYPE 3 Section 9.1.24"""
# This message has a L2 Pseudo Length of 19
    a = L2PseudoLength(l2pLength=0x13)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x24)  # 00100100
    d = PageModeAndChannelNeeded()
    e = TmsiPTmsi()
    f = TmsiPTmsi()
    g = TmsiPTmsi()
    h = TmsiPTmsi()
    i = P3RestOctets()
    packet = a / b / c / d / e / f / g / h / i
    return packet


def pagingResponse():
    """PAGING RESPONSE Section 9.1.25"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x27)  # 00100111
    c = CiphKeySeqNrAndSpareHalfOctets()
    d = MobileStationClassmark2()
    e = MobileId()
    packet = a / b / c / d / e
    return packet


# Network to MS
def partialRelease():
    """PARTIAL RELEASE Section 9.1.26"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0xa)  # 00001010
    c = ChannelDescription()
    packet = a / b / c
    return packet


def partialReleaseComplete():
    """PARTIAL RELEASE COMPLETE Section 9.1.27"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0xf)  # 00001111
    packet = a / b
    return packet


# Network to MS
def physicalInformation():
    """PHYSICAL INFORMATION Section 9.1.28"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2d)  # 00101101
    c = TimingAdvance()
    packet = a / b / c
    return packet


def rrInitialisationRequest():
    """RR Initialisation Request Section 9.1.28.a"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x3c)  # 00111100
    c = CiphKeySeqNrAndMacModeAndChannelCodingRequest()
    e = MobileStationClassmark2()
    f = Tlli()
    g = ChannelRequestDescription()
    h = GprsMeasurementResults()
    packet = a / b / c / e / f / g / h
    return packet


def rrStatus():
    """RR STATUS Section 9.1.29"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x12)  # 00010010
    c = RrCause()
    packet = a / b / c
    return packet


# It does not
# follow the basic format. Its length is _25_ bits. The
# order of bit transmission is defined in GSM 04.04.
# Network to MS
class SynchronizationChannelInformation():
    """SYNCHRONIZATION CHANNEL INFORMATION Section 9.1.30"""
    name = "Synchronization Channel Information"
    fields_desc = [
        BitField("bsic", 0x0, 5),
        BitField("t1Hi", 0x0, 3),
        ByteField("t1Mi", 0x0),
        BitField("t1Lo", 0x0, 1),
        BitField("t2", 0x0, 5),
        BitField("t3Hi", 0x0, 2),
        BitField("t3Lo", 0x0, 1)
    ]


# This message has a L2 Pseudo Length of 21.
# Network to MS
def systemInformationType1():
    """SYSTEM INFORMATION TYPE 1 Section 9.1.31"""
    a = L2PseudoLength(l2pLength=0x15)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x19)  # 00011001
    d = CellChannelDescription()
    e = RachControlParameters()
    f = Si1RestOctets()
    packet = a / b / c / d / e / f
    return packet


# This message has a L2 Pseudo Length of 22.
# Network to MS
def systemInformationType2():
    """SYSTEM INFORMATION TYPE 2 Section 9.1.32"""
    a = L2PseudoLength(l2pLength=0x16)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x1a)  # 00011010
    d = NeighbourCellsDescription()
    e = NccPermitted()
    f = RachControlParameters()
    packet = a / b / c / d / e / f
    return packet


# This message has a L2 pseudo length of 21
# Network to MS
def systemInformationType2bis():
    """SYSTEM INFORMATION TYPE 2bis Section 9.1.33"""
    a = L2PseudoLength(l2pLength=0x15)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x2)  # 00000010
    d = NeighbourCellsDescription()
    e = RachControlParameters()
    f = Si2bisRestOctets()
    packet = a / b / c / d / e / f
    return packet


# This message has a L2 pseudo length of 18
# Network to MS
def systemInformationType2ter():
    """SYSTEM INFORMATION TYPE 2ter Section 9.1.34"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x3)  # 00000011
    d = NeighbourCellsDescription2()
    e = Si2terRestOctets()
    packet = a / b / c / d / e
    return packet


# This message has a L2 Pseudo Length of 18
# Network to MS
def systemInformationType3():
    """SYSTEM INFORMATION TYPE 3 Section 9.1.35"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x1b)  # 00011011
    d = CellIdentity()
    e = LocalAreaId()
    f = ControlChannelDescription()
    g = CellOptionsBCCH()
    h = CellSelectionParameters()
    i = RachControlParameters()
    j = Si3RestOctets()
    packet = a / b / c / d / e / f / g / h / i / j
    return packet


# The L2 pseudo length of this message is the
# sum of lengths of all information elements present in the message except
# the SI 4 Rest Octets and L2 Pseudo Length
# Network to MS
def systemInformationType4(ChannelDescription_presence=0,
                           MobileAllocation_presence=0):
    """SYSTEM INFORMATION TYPE 4 Section 9.1.36"""
    a = L2PseudoLength()
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x1C)  # 000111100
    d = LocalAreaId()
    e = CellSelectionParameters()
    f = RachControlParameters()
    packet = a / b / c / d / e / f
    if ChannelDescription_presence is 1:
        g = ChannelDescriptionHdr(ieiCD=0x64, eightBitCD=0x0)
        packet = packet / g
    if MobileAllocation_presence is 1:
        h = MobileAllocationHdr(ieiMA=0x72, eightBitMA=0x0)
        packet = packet / h
    i = Si4RestOctets()
    packet = packet / i
    return packet


# This message has a L2 Pseudo Length of 18
# Network to MS
def systemInformationType5():
    """SYSTEM INFORMATION TYPE 5 Section 9.1.37"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x35)  # 000110101
    d = NeighbourCellsDescription()
    packet = a / b / c / d
    return packet


# This message has a L2 Pseudo Length of 18
# Network to MS
def systemInformationType5bis():
    """SYSTEM INFORMATION TYPE 5bis Section 9.1.38"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x5)  # 00000101
    d = NeighbourCellsDescription()
    packet = a / b / c / d
    return packet


# This message has a L2 Pseudo Length of 18
# Network to MS
def systemInformationType5ter():
    """SYSTEM INFORMATION TYPE 5ter Section 9.1.39"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x6)  # 00000110
    d = NeighbourCellsDescription2()
    packet = a / b / c / d
    return packet


# This message has a L2 Pseudo Length of 11
# Network to MS
def systemInformationType6():
    """SYSTEM INFORMATION TYPE 6 Section 9.1.40"""
    a = L2PseudoLength(l2pLength=0x0b)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x1e)  # 00011011
    d = CellIdentity()
    e = LocalAreaId()
    f = CellOptionsBCCH()
    g = NccPermitted()
    h = Si6RestOctets()
    packet = a / b / c / d / e / f / g
    return packet


# The L2 pseudo length of this message has the value 1
# Network to MS
def systemInformationType7():
    """SYSTEM INFORMATION TYPE 7 Section 9.1.41"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x37)  # 000110111
    d = Si7RestOctets()
    packet = a / b / c / d
    return packet


# The L2 pseudo length of this message has the value 1
# Network to MS
def systemInformationType8():
    """SYSTEM INFORMATION TYPE 8 Section 9.1.42"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x18)  # 00011000
    d = Si8RestOctets()
    packet = a / b / c / d
    return packet


# The L2 pseudo length of this message has the value 1
# Network to MS
def systemInformationType9():
    """SYSTEM INFORMATION TYPE 9 Section 9.1.43"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x4)  # 00000100
    d = Si9RestOctets()
    packet = a / b / c / d
    return packet


# The L2 pseudo length of this message has the value 0
# Network to MS
def systemInformationType13():
    """SYSTEM INFORMATION TYPE 13 Section 9.1.43a"""
    a = L2PseudoLength(l2pLength=0x00)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x0)  # 00000000
    d = Si13RestOctets()
    packet = a / b / c / d
    return packet
#
# 9.1.43b / c spare
#


# The L2 pseudo length of this message has the value 1
# Network to MS
def systemInformationType16():
    """SYSTEM INFORMATION TYPE 16 Section 9.1.43d"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x3d)  # 00111101
    d = Si16RestOctets()
    packet = a / b / c / d
    return packet


# The L2 pseudo length of this message has the value 1
# Network to MS
def systemInformationType17():
    """SYSTEM INFORMATION TYPE 17 Section 9.1.43e"""
    a = L2PseudoLength(l2pLength=0x01)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x3e)  # 00111110
    d = Si17RestOctets()
    packet = a / b / c / d
    return packet


def talkerIndication():
    """TALKER INDICATION Section 9.1.44"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x11)  # 00010001
    c = MobileStationClassmark2()
    d = MobileId()
    packet = a / b / c / d
    return packet


class UplinkAccess():
    """UPLINK ACCESS Section 9.1.45"""
    name = "Uplink Access"
    fields_desc = [
        ByteField("establishment", 0x0)
    ]


# Network to MS
def uplinkBusy():
    """UPLINK BUSY Section 9.1.46"""
    name = "Uplink Busy"
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x2a)  # 00101010
    packet = a / b
    return packet


# Network to MS
class UplinkFree():
    """UPLINK FREE Section 9.1.47"""
    name = "Uplink Free"
    fields_desc = [
        BitField("pd", 0x0, 1),
        BitField("msgType", 0x0, 5),
        BitField("layer2Header", 0x0, 2),
        BitField("uplinkAccess", 0x0, 1),
        BitField("lOrH", 0x0, 1),  # 0 for L, 1 for H
        BitField("upIdCode", 0x0, 6),
    ]


def uplinkRelease():
    """UPLINK RELEASE Section 9.1.48"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0xe)  # 00001110
    c = RrCause()
    packet = a / b / c
    return packet


# Network to MS
def vgcsUplinkGrant():
    """VGCS UPLINK GRANT Section 9.1.49"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x9)  # 00001001
    c = RrCause()
    d = RequestReference()
    e = TimingAdvance()
    packet = a / b / c / d / e
    return packet


# Network to MS
def systemInformationType10():
    """SYSTEM INFORMATION TYPE 10 Section 9.1.50"""
    name = "SyStem Information Type 10"
    fields_desc = [
        BitField("pd", 0x0, 1),
        BitField("msgType", 0x0, 5),
        BitField("layer2Header", 0x0, 2),
        BitField("si10", 0x0, 160)
    ]


# Network to MS
# The L2 pseudo length of this message has the value 18
def extendedMeasurementOrder():
    """EXTENDED MEASUREMENT ORDER Section 9.1.51"""
    a = L2PseudoLength(l2pLength=0x12)
    b = TpPd(pd=0x6)
    c = MessageType(mesType=0x37)  # 00110111
    d = ExtendedMeasurementFrequencyList()
    packet = a / b / c / d
    return packet


def extendedMeasurementReport():
    """EXTENDED MEASUREMENT REPORT Section 9.1.52"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x36)  # 00110110
    c = ExtendedMeasurementResults()
    packet = a / b / c
    return packet


def applicationInformation():
    """APPLICATION INFORMATION Section 9.1.53"""
    a = TpPd(pd=0x6)
    b = MessageType(mesType=0x38)  # 00111000
    c = ApduIDAndApduFlags()
    e = ApduData()
    packet = a / b / c / e
    return packet
#
# 9.2 Messages for mobility management
#


# Network to MS
def authenticationReject():
    """AUTHENTICATION REJECT Section 9.2.1"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x11)  # 00010001
    packet = a / b
    return packet


# Network to MS
def authenticationRequest():
    """AUTHENTICATION REQUEST Section 9.2.2"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x12)  # 00010010
    c = CiphKeySeqNrAndSpareHalfOctets()
    d = AuthenticationParameterRAND()
    packet = a / b / c / d
    return packet


def authenticationResponse():
    """AUTHENTICATION RESPONSE Section 9.2.3"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x14)  # 00010100
    c = AuthenticationParameterSRES()
    packet = a / b / c
    return packet


def cmReestablishmentRequest(LocalAreaId_presence=0):
    """CM RE-ESTABLISHMENT REQUEST Section 9.2.4"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x28)  # 00101000
    c = CiphKeySeqNrAndSpareHalfOctets()
    e = MobileStationClassmark2()
    f = MobileId()
    if LocalAreaId_presence is 1:
        g = LocalAreaId(iei=0x13, eightbit=0x0)
        packet = packet / g
    packet = a / b / c / e / f
    return packet


# Network to MS
def cmServiceAccept():
    """CM SERVICE ACCEPT Section 9.2.5"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x21)  # 00100001
    packet = a / b
    return packet


# Network to MS
def cmServicePrompt():
    """CM SERVICE PROMPT Section 9.2.5a"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x25)  # 00100101
    c = PdAndSapi()
    packet = a / b / c
    return packet


# Network to MS
def cmServiceReject():
    """CM SERVICE REJECT Section 9.2.6"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x22)  # 00100010
    c = RejectCause()
    packet = a / b / c
    return packet


def cmServiceAbort():
    """CM SERVICE ABORT Section 9.2.7"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x23)  # 00100011
    packet = a / b
    return packet


# Network to MS
def abort():
    """ABORT Section 9.2.8"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x29)  # 00101001
    c = RejectCause()
    packet = a / b / c
    return packet


def cmServiceRequest(PriorityLevel_presence=0):
    """CM SERVICE REQUEST Section 9.2.9"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x24)  # 00100100
    c = CmServiceTypeAndCiphKeySeqNr()
    e = MobileStationClassmark2()
    f = MobileId()
    packet = a / b / c / e / f
    if PriorityLevel_presence is 1:
        g = PriorityLevelHdr(ieiPL=0x8, eightBitPL=0x0)
        packet = packet / g
    return packet


# Network to MS
def identityRequest():
    """IDENTITY REQUEST Section 9.2.10"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x8)  # 00001000
    c = IdentityTypeAndSpareHalfOctets()
    packet = a / b / c
    return packet


def identityResponse():
    """IDENTITY RESPONSE Section 9.2.11"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x9)  # 00001001
    c = MobileId()
    packet = a / b / c
    return packet


def imsiDetachIndication():
    """IMSI DETACH INDICATION Section 9.2.12"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x1)  # 00000001
    c = MobileStationClassmark1()
    d = MobileId()
    packet = a / b / c / d
    return packet


# Network to MS
def locationUpdatingAccept(MobileId_presence=0,
                           FollowOnProceed_presence=0,
                           CtsPermission_presence=0):
    """LOCATION UPDATING ACCEPT Section 9.2.13"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x02)  # 00000010
    c = LocalAreaId()
    packet = a / b / c
    if MobileId_presence is 1:
        d = MobileIdHdr(ieiMI=0x17, eightBitMI=0x0)
        packet = packet / d
    if FollowOnProceed_presence is 1:
        e = FollowOnProceed(ieiFOP=0xA1)
        packet = packet / e
    if CtsPermission_presence is 1:
        f = CtsPermissionHdr(ieiCP=0xA2, eightBitCP=0x0)
        packet = packet / f
    return packet


# Network to MS
def locationUpdatingReject():
    """LOCATION UPDATING REJECT Section 9.2.14"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x4)  # 0x00000100
    c = RejectCause()
    packet = a / b / c
    return packet


def locationUpdatingRequest():
    """LOCATION UPDATING REQUEST Section 9.2.15"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x8)  # 00001000
    c = LocationUpdatingTypeAndCiphKeySeqNr()
    e = LocalAreaId()
    f = MobileStationClassmark1()
    g = MobileId()
    packet = a / b / c / e / f / g
    return packet


# Network to MS
def mmInformation(NetworkName_presence=0, NetworkName_presence1=0,
                  TimeZone_presence=0, TimeZoneAndTime_presence=0,
                  LsaIdentifier_presence=0):
    """MM INFORMATION Section 9.2.15a"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x32)  # 00110010
    packet = a / b
    if NetworkName_presence is 1:
        c = NetworkNameHdr(ieiNN=0x43, eightBitNN=0x0)
        packet = packet / c
    if NetworkName_presence1 is 1:
        d = NetworkNameHdr(ieiNN=0x45, eightBitNN=0x0)
        packet = packet / d
    if TimeZone_presence is 1:
        e = TimeZoneHdr(ieiTZ=0x46, eightBitTZ=0x0)
        packet = packet / e
    if TimeZoneAndTime_presence is 1:
        f = TimeZoneAndTimeHdr(ieiTZAT=0x47, eightBitTZAT=0x0)
        packet = packet / f
    if LsaIdentifier_presence is 1:
        g = LsaIdentifierHdr(ieiLI=0x48, eightBitLI=0x0)
        packet = packet / g
    return packet


def mmStatus():
    """MM STATUS Section 9.2.16"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x31)  # 00110001
    c = RejectCause()
    packet = a / b / c
    return packet


# Network to MS
def tmsiReallocationCommand():
    """TMSI REALLOCATION COMMAND Section 9.2.17"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x1a)  # 00011010
    c = LocalAreaId()
    d = MobileId()
    packet = a / b / c / d
    return packet


def tmsiReallocationComplete():
    """TMSI REALLOCATION COMPLETE Section 9.2.18"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x1b)  # 00011011
    packet = a / b
    return packet


def mmNull():
    """MM NULL Section 9.2.19"""
    a = TpPd(pd=0x5)
    b = MessageType(mesType=0x30)  # 00110000
    packet = a / b
    return packet

#
# 9.3 Messages for circuit-switched call control
#


# Network to MS
def alertingNetToMs(Facility_presence=0, ProgressIndicator_presence=0,
                    UserUser_presence=0):
    """ALERTING Section 9.3.1.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1)  # 00000001
    packet = a / b
    if Facility_presence is 1:
        c = FacilityHdr(ieiF=0x1C)
        packet = packet / c
    if ProgressIndicator_presence is 1:
        d = ProgressIndicatorHdr(ieiPI=0x1E)
        packet = packet / d
    if UserUser_presence is 1:
        e = UserUserHdr(ieiUU=0x7E)
        packet = packet / e
    return packet


def alertingMsToNet(Facility_presence=0, UserUser_presence=0,
                    SsVersionIndicator_presence=0):
    """ALERTING Section 9.3.1.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1)  # 00000001
    packet = a / b
    if Facility_presence is 1:
        c = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / c
    if UserUser_presence is 1:
        d = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / d
    if SsVersionIndicator_presence is 1:
        e = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / e
    return packet


def callConfirmed(RepeatIndicator_presence=0,
                  BearerCapability_presence=0, BearerCapability_presence1=0,
                  Cause_presence=0, CallControlCapabilities_presence=0):
    """CALL CONFIRMED Section 9.3.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x8)  # 00001000
    packet = a / b
    if RepeatIndicator_presence is 1:
        c = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / c
    if BearerCapability_presence is 1:
        d = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / d
    if BearerCapability_presence1 is 1:
        e = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / e
    if Cause_presence is 1:
        f = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / f
    if CallControlCapabilities_presence is 1:
        g = CallControlCapabilitiesHdr(ieiCCC=0x15, eightBitCCC=0x0)
        packet = packet / g
    return packet


# Network to MS
def callProceeding(RepeatIndicator_presence=0,
                   BearerCapability_presence=0,
                   BearerCapability_presence1=0,
                   Facility_presence=0, ProgressIndicator_presence=0,
                   PriorityLevel_presence=0):
    """CALL PROCEEDING Section 9.3.3"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2)  # 00000010
    packet = a / b
    if RepeatIndicator_presence is 1:
        c = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / c
    if BearerCapability_presence is 1:
        d = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / d
    if BearerCapability_presence1 is 1:
        e = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / e
    if Facility_presence is 1:
        f = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / f
    if ProgressIndicator_presence is 1:
        g = ProgressIndicatorHdr(ieiPI=0x1E, eightBitPI=0x0)
        packet = packet / g
    if PriorityLevel_presence is 1:
        h = PriorityLevelHdr(ieiPL=0x80, eightBitPL=0x0)
        packet = packet / h
    return packet


# Network to MS
def congestionControl(Cause_presence=0):
    """CONGESTION CONTROL Section 9.3.4"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x39)  # 00111001
    c = CongestionLevelAndSpareHalfOctets()
    packet = a / b / c
    if Cause_presence is 1:
        e = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / e
    return packet


# Network to MS
def connectNetToMs(Facility_presence=0, ProgressIndicator_presence=0,
                   ConnectedNumber_presence=0, ConnectedSubaddress_presence=0,
                   UserUser_presence=0):
    """CONNECT Section 9.3.5.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x7)  # 00000111
    packet = a / b
    if Facility_presence is 1:
        c = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / c
    if ProgressIndicator_presence is 1:
        d = ProgressIndicatorHdr(ieiPI=0x1E, eightBitPI=0x0)
        packet = packet / d
    if ConnectedNumber_presence is 1:
        e = ConnectedNumberHdr(ieiCN=0x4C, eightBitCN=0x0)
        packet = packet / e
    if ConnectedSubaddress_presence is 1:
        f = ConnectedSubaddressHdr(ieiCS=0x4D, eightBitCS=0x0)
        packet = packet / f
    if UserUser_presence is 1:
        g = UserUserHdr(ieiUU=0x7F, eightBitUU=0x0)
        packet = packet / g
    return packet


def connectMsToNet(Facility_presence=0, ConnectedSubaddress_presence=0,
                   UserUser_presence=0, SsVersionIndicator_presence=0):
    """CONNECT Section 9.3.5.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x7)  # 00000111
    packet = a / b
    if Facility_presence is 1:
        c = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / c
    if ConnectedSubaddress_presence is 1:
        d = ConnectedSubaddressHdr(ieiCS=0x4D, eightBitCS=0x0)
        packet = packet / d
    if UserUser_presence is 1:
        e = UserUserHdr(ieiUU=0x7F, eightBitUU=0x0)
        packet = packet / e
    if SsVersionIndicator_presence is 1:
        f = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / f
    return packet


def connectAcknowledge():
    """CONNECT ACKNOWLEDGE Section 9.3.6"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0xf)  # 00001111
    packet = a / b
    return packet


# Network to MS
def disconnectNetToMs(Facility_presence=0, ProgressIndicator_presence=0,
                      UserUser_presence=0, AllowedActions_presence=0):
    """DISCONNECT Section 9.3.7.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x25)  # 00100101
    c = Cause()
    packet = a / b / c
    if Facility_presence is 1:
        d = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / d
    if ProgressIndicator_presence is 1:
        e = ProgressIndicatorHdr(ieiPI=0x1E, eightBitPI=0x0)
        packet = packet / e
    if UserUser_presence is 1:
        f = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / f
    if AllowedActions_presence is 1:
        g = AllowedActionsHdr(ieiAA=0x7B, eightBitAA=0x0)
        packet = packet / g
    return packet


def disconnectMsToNet(Facility_presence=0, UserUser_presence=0,
                      SsVersionIndicator_presence=0):
    """Disconnect Section 9.3.7.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x25)  # 00100101
    c = Cause()
    packet = a / b / c
    if Facility_presence is 1:
        d = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / d
    if UserUser_presence is 1:
        e = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / e
    if SsVersionIndicator_presence is 1:
        f = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / f
    return packet


def emergencySetup(BearerCapability_presence=0):
    """EMERGENCY SETUP Section 9.3.8"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0xe)  # 00001110
    packet = a / b
    if BearerCapability_presence is 1:
        c = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / c
    return packet


# Network to MS
def facilityNetToMs():
    """FACILITY Section 9.3.9.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3a)  # 00111010
    c = Facility()
    packet = a / b / c
    return packet


def facilityMsToNet(SsVersionIndicator_presence=0):
    """FACILITY Section 9.3.9.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3a)  # 00111010
    c = Facility()
    packet = a / b / c
    if SsVersionIndicator_presence is 1:
        d = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / d
    return packet


def hold():
    """HOLD Section 9.3.10"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x18)  # 00011000
    packet = a / b
    return packet


# Network to MS
def holdAcknowledge():
    """HOLD ACKNOWLEDGE Section 9.3.11"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x19)  # 00011001
    packet = a / b
    return packet


# Network to MS
def holdReject():
    """HOLD REJECT Section 9.3.12"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1a)  # 00011010
    c = Cause()
    packet = a / b / c
    return packet


def modify(LowLayerCompatibility_presence=0,
           HighLayerCompatibility_presence=0,
           ReverseCallSetupDirection_presence=0):
    """MODIFY Section 9.3.13"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x17)  # 00010111
    c = BearerCapability()
    packet = a / b / c
    if LowLayerCompatibility_presence is 1:
        d = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / d
    if HighLayerCompatibility_presence is 1:
        e = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / e
    if ReverseCallSetupDirection_presence is 1:
        f = ReverseCallSetupDirectionHdr(ieiRCSD=0xA3)
        packet = packet / f
    return packet


def modifyComplete(LowLayerCompatibility_presence=0,
                   HighLayerCompatibility_presence=0,
                   ReverseCallSetupDirection_presence=0):
    """MODIFY COMPLETE Section 9.3.14"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1f)  # 00011111
    c = BearerCapability()
    packet = a / b / c
    if LowLayerCompatibility_presence is 1:
        d = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / d
    if HighLayerCompatibility_presence is 1:
        e = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / e
    if ReverseCallSetupDirection_presence is 1:
        f = ReverseCallSetupDirection(ieiRCSD=0xA3)
        packet = packet / f
    return packet


def modifyReject(LowLayerCompatibility_presence=0,
                 HighLayerCompatibility_presence=0):
    """MODIFY REJECT Section 9.3.15"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x13)  # 00010011
    c = BearerCapability()
    d = Cause()
    packet = a / b / c / d
    if LowLayerCompatibility_presence is 1:
        e = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / e
    if HighLayerCompatibility_presence is 1:
        f = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / f
    return packet


def notify():
    """NOTIFY Section 9.3.16"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3e)  # 00111110
    c = NotificationIndicator()
    packet = a / b / c
    return packet


# Network to MS
def progress(UserUser_presence=0):
    """PROGRESS Section 9.3.17"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3)  # 00000011
    c = ProgressIndicator()
    packet = a / b / c
    if UserUser_presence is 1:
        d = UserUserHdr()
        packet = packet / d
    return packet


# Network to MS
def ccEstablishment():
    """CC-ESTABLISHMENT Section 9.3.17a"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x4)  # 00000100
    c = SetupContainer()
    packet = a / b / c
    return packet


def ccEstablishmentConfirmed(RepeatIndicator_presence=0,
                             BearerCapability_presence=0,
                             BearerCapability_presence1=0,
                             Cause_presence=0):
    """CC-ESTABLISHMENT CONFIRMED Section 9.3.17b"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x6)  # 00000110
    packet = a / b
    if RepeatIndicator_presence is 1:
        c = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / c
    if BearerCapability_presence is 1:
        d = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / d
    if BearerCapability_presence1 is 1:
        e = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / e
    if Cause_presence is 1:
        f = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / f
    return packet


# Network to MS
def releaseNetToMs():
    """RELEASE Section 9.3.18.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2d)  # 00101101
    c = CauseHdr(ieiC=0x08, eightBitC=0x0)
    d = CauseHdr(ieiC=0x08, eightBitC=0x0)
    e = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
    f = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
    packet = a / b / c / d / e / f
    return packet


def releaseMsToNet(Cause_presence=0, Cause_presence1=0,
                   Facility_presence=0, UserUser_presence=0,
                   SsVersionIndicator_presence=0):
    """RELEASE Section 9.3.18.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2d)  # 00101101
    packet = a / b
    if Cause_presence is 1:
        c = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / c
    if Cause_presence1 is 1:
        d = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / d
    if Facility_presence is 1:
        e = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / e
    if UserUser_presence is 1:
        f = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / f
    if SsVersionIndicator_presence is 1:
        g = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / g
    return packet


# Network to MS
def recall():
    """RECALL Section 9.3.18a"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0xb)  # 00001011
    c = RecallType()
    d = Facility()
    packet = a / b / c / d
    return packet


# Network to MS
def releaseCompleteNetToMs(Cause_presence=0, Facility_presence=0,
                           UserUser_presence=0):
    """RELEASE COMPLETE Section 9.3.19.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2a)  # 00101010
    packet = a / b
    if Cause_presence is 1:
        c = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / c
    if Facility_presence is 1:
        d = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / d
    if UserUser_presence is 1:
        e = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / e
    return packet


def releaseCompleteMsToNet(Cause_presence=0, Facility_presence=0,
                           UserUser_presence=0, SsVersionIndicator_presence=0):
    """RELEASE COMPLETE Section 9.3.19.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2a)  # 00101010
    packet = a / b
    if Cause_presence is 1:
        c = CauseHdr(ieiC=0x08, eightBitC=0x0)
        packet = packet / c
    if Facility_presence is 1:
        d = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / d
    if UserUser_presence is 1:
        e = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / e
    if SsVersionIndicator_presence is 1:
        f = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / f
    return packet


def retrieve():
    """RETRIEVE Section 9.3.20"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1c)  # 00011100
    packet = a / b
    return packet


# Network to MS
def retrieveAcknowledge():
    """RETRIEVE ACKNOWLEDGE Section 9.3.21"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1d)  # 00011101
    packet = a / b
    return packet


# Network to MS
def retrieveReject():
    """RETRIEVE REJECT Section 9.3.22"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1e)  # 00011110
    c = Cause()
    packet = a / b / c
    return packet


# Network to MS
def setupMobileTerminated(RepeatIndicator_presence=0,
                          BearerCapability_presence=0,
                          BearerCapability_presence1=0,
                          Facility_presence=0, ProgressIndicator_presence=0,
                          Signal_presence=0,
                          CallingPartyBcdNumber_presence=0,
                          CallingPartySubaddress_presence=0,
                          CalledPartyBcdNumber_presence=0,
                          CalledPartySubaddress_presence=0,
                          #                          RecallType_presence=0,
                          RedirectingPartyBcdNumber_presence=0,
                          RedirectingPartySubaddress_presence=0,
                          RepeatIndicator_presence1=0,
                          LowLayerCompatibility_presence=0,
                          LowLayerCompatibility_presence1=0,
                          RepeatIndicator_presence2=0,
                          HighLayerCompatibility_presence=0,
                          HighLayerCompatibility_presence1=0,
                          UserUser_presence=0, PriorityLevel_presence=0,
                          AlertingPattern_presence=0):
    """SETUP Section 9.3.23.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x5)  # 00000101
    packet = a / b
    if RepeatIndicator_presence is 1:
        c = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / c
    if BearerCapability_presence is 1:
        d = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / d
    if BearerCapability_presence1 is 1:
        e = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / e
    if Facility_presence is 1:
        f = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / f
    if ProgressIndicator_presence is 1:
        g = ProgressIndicatorHdr(ieiPI=0x1E, eightBitPI=0x0)
        packet = packet / g
    if Signal_presence is 1:
        h = SignalHdr(ieiS=0x34, eightBitS=0x0)
        packet = packet / h
    if CallingPartyBcdNumber_presence is 1:
        i = CallingPartyBcdNumberHdr(ieiCPBN=0x5C, eightBitCPBN=0x0)
        packet = packet / i
    if CallingPartySubaddress_presence is 1:
        j = CallingPartySubaddressHdr(ieiCPS=0x5D, eightBitCPS=0x0)
        packet = packet / j
    if CalledPartyBcdNumber_presence is 1:
        k = CalledPartyBcdNumberHdr(ieiCPBN=0x5E, eightBitCPBN=0x0)
        packet = packet / k
    if CalledPartySubaddress_presence is 1:
        l = CalledPartySubaddressHdr(ieiCPS=0x6D, eightBitCPS=0x0)
        packet = packet / l
    if RedirectingPartyBcdNumber_presence is 1:
        n = RedirectingPartyBcdNumberHdr(ieiRPBN=0x74, eightBitRPBN=0x0)
        packet = packet / n
    if RedirectingPartySubaddress_presence is 1:
        m = RedirectingPartySubaddress_presence(ieiRPBN=0x75, eightBitRPBN=0x0)
        packet = packet / m
    if RepeatIndicator_presence1 is 1:
        o = RepeatIndicatorHdr(ieiRI=0xD0, eightBitRI=0x0)
        packet = packet / o
    if LowLayerCompatibility_presence is 1:
        p = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / p
    if LowLayerCompatibility_presence1 is 1:
        q = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / q
    if RepeatIndicator_presence2 is 1:
        r = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / r
    if HighLayerCompatibility_presence is 1:
        s = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / s
    if HighLayerCompatibility_presence1 is 1:
        t = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / t
    if UserUser_presence is 1:
        u = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / u
    if PriorityLevel_presence is 1:
        v = PriorityLevelHdr(ieiPL=0x8, eightBitPL=0x0)
        packet = packet / v
    if AlertingPattern_presence is 1:
        w = AlertingPatternHdr(ieiAP=0x19, eightBitAP=0x0)
        packet = packet / w
    return packet


def setupMobileOriginated(RepeatIndicator_presence=0,
                          BearerCapability_presence=0,
                          BearerCapability_presence1=0,
                          Facility_presence=0,
                          CallingPartySubaddress_presence=0,
                          CalledPartyBcdNumber_presence=0,
                          CalledPartySubaddress_presence=0,
                          RepeatIndicator_presence1=0,
                          LowLayerCompatibility_presence=0,
                          LowLayerCompatibility_presence1=0,
                          RepeatIndicator_presence2=0,
                          HighLayerCompatibility_presence=0,
                          HighLayerCompatibility_presence1=0,
                          UserUser_presence=0, SsVersionIndicator_presence=0,
                          ClirSuppression_presence=0,
                          ClirInvocation_presence=0,
                          CallControlCapabilities_presence=0,
                          Facility_presence1=0,
                          Facility_presence2=0):
    """SETUP Section 9.3.23.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x5)  # 00000101
    packet = a / b
    if RepeatIndicator_presence is 1:
        c = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / c
    if BearerCapability_presence is 1:
        d = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / d
    if BearerCapability_presence1 is 1:
        e = BearerCapabilityHdr(ieiBC=0x04, eightBitBC=0x0)
        packet = packet / e
    if Facility_presence is 1:
        f = FacilityHdr(ieiF=0x1C, eightBitF=0x0)
        packet = packet / f
    if CallingPartySubaddress_presence is 1:
        g = CallingPartySubaddressHdr(ieiCPS=0x5D, eightBitCPS=0x0)
        packet = packet / g
    if CalledPartyBcdNumber_presence is 1:
        h = CalledPartyBcdNumberHdr(ieiCPBN=0x5E, eightBitCPBN=0x0)
        packet = packet / h
    if CalledPartySubaddress_presence is 1:
        i = CalledPartySubaddressHdr(ieiCPS=0x6D, eightBitCPS=0x0)
        packet = packet / i
    if RepeatIndicator_presence1 is 1:
        j = RepeatIndicatorHdr(ieiRI=0xD0, eightBitRI=0x0)
        packet = packet / j
    if LowLayerCompatibility_presence is 1:
        k = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / k
    if LowLayerCompatibility_presence1 is 1:
        l = LowLayerCompatibilityHdr(ieiLLC=0x7C, eightBitLLC=0x0)
        packet = packet / l
    if RepeatIndicator_presence2 is 1:
        m = RepeatIndicatorHdr(ieiRI=0xD, eightBitRI=0x0)
        packet = packet / m
    if HighLayerCompatibility_presence is 1:
        n = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / n
    if HighLayerCompatibility_presence1 is 1:
        o = HighLayerCompatibilityHdr(ieiHLC=0x7D, eightBitHLC=0x0)
        packet = packet / o
    if UserUser_presence is 1:
        p = UserUserHdr(ieiUU=0x7E, eightBitUU=0x0)
        packet = packet / p
    if SsVersionIndicator_presence is 1:
        q = SsVersionIndicatorHdr(ieiSVI=0x7F, eightBitSVI=0x0)
        packet = packet / q
    if ClirSuppression_presence is 1:
        r = ClirSuppressionHdr(ieiCS=0xA1, eightBitCS=0x0)
        packet = packet / r
    if ClirInvocation_presence is 1:
        s = ClirInvocationHdr(ieiCI=0xA2, eightBitCI=0x0)
        packet = packet / s
    if CallControlCapabilities_presence is 1:
        t = CallControlCapabilitiesHdr(ieiCCC=0x15, eightBitCCC=0x0)
        packet = packet / t
    if Facility_presence1 is 1:
        u = FacilityHdr(ieiF=0x1D, eightBitF=0x0)
        packet = packet / u
    if Facility_presence2 is 1:
        v = FacilityHdr(ieiF=0x1B, eightBitF=0x0)
        packet = packet / v
    return packet


def startCc(CallControlCapabilities_presence=0):
    """START CC Section 9.3.23a"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x9)  # 00001001
    packet = a / b
    if CallControlCapabilities_presence is 1:
        c = CallControlCapabilitiesHdr(ieiCCC=0x15, eightBitCCC=0x0)
        packet = packet / c
    return packet


def startDtmf():
    """START DTMF Section 9.3.24"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x35)  # 00110101
    c = KeypadFacilityHdr(ieiKF=0x2C, eightBitKF=0x0)
    packet = a / b / c
    return packet


# Network to MS
def startDtmfAcknowledge():
    """START DTMF ACKNOWLEDGE Section 9.3.25"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x32)  # 00110010
    c = KeypadFacilityHdr(ieiKF=0x2C, eightBitKF=0x0)
    packet = a / b / c
    return packet


# Network to MS
def startDtmfReject():
    """ START DTMF REJECT Section 9.3.26"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x37)  # 00110111
    c = Cause()
    packet = a / b / c
    return packet


def status(AuxiliaryStates_presence=0):
    """STATUS Section 9.3.27"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3d)  # 00111101
    c = Cause()
    d = CallState()
    packet = a / b / c / d
    if AuxiliaryStates_presence is 1:
        e = AuxiliaryStatesHdr(ieiAS=0x24, eightBitAS=0x0)
        packet = packet / e
    return packet


def statusEnquiry():
    """STATUS ENQUIRY Section 9.3.28"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x34)  # 00110100
    packet = a / b
    return packet


def stopDtmf():
    """STOP DTMF Section 9.3.29"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x31)  # 00110001
    packet = a / b
    return packet


# Network to MS
def stopDtmfAcknowledge():
    """STOP DTMF ACKNOWLEDGE Section 9.3.30"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x32)  # 00110010
    packet = a / b
    return packet


def userInformation(MoreData_presence=0):
    """USER INFORMATION Section 9.3.31"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x20)  # 000100000
    c = UserUser()
    packet = a / b / c
    if MoreData_presence is 1:
        d = MoreDataHdr(ieiMD=0xA0, eightBitMD=0x0)
        packet = packet / d
    return packet

#
# 9.4 GPRS Mobility Management Messages
#


def attachRequest(PTmsiSignature_presence=0, GprsTimer_presence=0,
                  TmsiStatus_presence=0):
    """ATTACH REQUEST Section 9.4.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1)  # 0000001
    c = MsNetworkCapability()
    d = AttachTypeAndCiphKeySeqNr()
    f = DrxParameter()
    g = MobileId()
    h = RoutingAreaIdentification()
    i = MsRadioAccessCapability()
    packet = a / b / c / d / f / g / h / i
    if PTmsiSignature_presence is 1:
        j = PTmsiSignature(ieiPTS=0x19)
        packet = packet / j
    if GprsTimer_presence is 1:
        k = GprsTimer(ieiGT=0x17)
        packet = packet / k
    if TmsiStatus_presence is 1:
        l = TmsiStatus(ieiTS=0x9)
        packet = packet / l
    return packet


def attachAccept(PTmsiSignature_presence=0, GprsTimer_presence=0,
                 MobileId_presence=0, MobileId_presence1=0,
                 GmmCause_presence=0):
    """ATTACH ACCEPT Section 9.4.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x2)  # 00000010
    c = AttachResult()
    d = ForceToStandby()
    e = GprsTimer()
    f = RadioPriorityAndSpareHalfOctets()
    h = RoutingAreaIdentification()
    packet = a / b / c / d / e / f / h
    if PTmsiSignature_presence is 1:
        i = PTmsiSignature(ieiPTS=0x19)
        packet = packet / i
    if GprsTimer_presence is 1:
        j = GprsTimer(ieiGT=0x17)
        packet = packet / j
    if MobileId_presence is 1:
        k = MobileIdHdr(ieiMI=0x18, eightBitMI=0x0)
        packet = packet / k
    if MobileId_presence1 is 1:
        l = MobileIdHdr(ieiMI=0x23, eightBitMI=0x0)
        packet = packet / l
    if GmmCause_presence is 1:
        m = GmmCause(ieiGC=0x25)
        packet = packet / m
    return packet


def attachComplete():
    """ATTACH COMPLETE Section 9.4.3"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x3)  # 00000011
    packet = a / b
    return packet


def attachReject():
    """ATTACH REJECT Section 9.4.4"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x1)  # 00000001
    c = GmmCause()
    packet = a / b / c
    return packet


def detachRequest(GmmCause_presence=0):
    """DETACH REQUEST Section 9.4.5"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x5)  # 00000101
    c = DetachTypeAndForceToStandby()
    packet = a / b / c
    if GmmCause_presence is 1:
        e = GmmCause(ieiGC=0x25)
        packet = packet / e
    return packet


def detachRequestMsOriginating():
    """DETACH REQUEST Section 9.4.5.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x5)  # 00000101
    c = DetachTypeAndSpareHalfOctets()
    packet = a / b / c
    return packet


def detachAcceptMsTerminated():
    """DETACH ACCEPT Section 9.4.6.1"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x6)  # 00000110
    packet = a / b
    return packet


def detachAcceptMsOriginating():
    """DETACH ACCEPT Section 9.4.6.2"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x6)  # 00000110
    c = ForceToStandbyAndSpareHalfOctets()
    packet = a / b / c
    return packet


def ptmsiReallocationCommand(PTmsiSignature_presence=0):
    """P-TMSI REALLOCATION COMMAND Section 9.4.7"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x10)  # 00010000
    c = MobileId()
    d = RoutingAreaIdentification()
    e = ForceToStandbyAndSpareHalfOctets()
    packet = a / b / c / d / e
    if PTmsiSignature_presence is 1:
        g = PTmsiSignature(ieiPTS=0x19)
        packet = packet / g
    return packet


def ptmsiReallocationComplete():
    """P-TMSI REALLOCATION COMPLETE Section 9.4.8"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x11)  # 00010001
    packet = a / b
    return packet


def authenticationAndCipheringRequest(
        AuthenticationParameterRAND_presence=0,
        CiphKeySeqNr_presence=0):
    """AUTHENTICATION AND CIPHERING REQUEST Section 9.4.9"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x12)  # 00010010
    d = CipheringAlgorithmAndImeisvRequest()
    e = ForceToStandbyAndAcReferenceNumber()
    packet = a / b / d / e
    if AuthenticationParameterRAND_presence is 1:
        g = AuthenticationParameterRAND(ieiAPR=0x21)
        packet = packet / g
    if CiphKeySeqNr_presence is 1:
        h = CiphKeySeqNrHdr(ieiCKSN=0x08, eightBitCKSN=0x0)
        packet = packet / h
    return packet


def authenticationAndCipheringResponse(
        AuthenticationParameterSRES_presence=0,
        MobileId_presence=0):
    """AUTHENTICATION AND CIPHERING RESPONSE Section 9.4.10"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x13)  # 00010011
    c = AcReferenceNumberAndSpareHalfOctets()
    packet = a / b / c
    if AuthenticationParameterSRES_presence is 1:
        e = AuthenticationParameterSRES(ieiAPS=0x22)
        packet = packet / e
    if MobileId_presence is 1:
        f = MobileIdHdr(ieiMI=0x23, eightBitMI=0x0)
        packet = packet / f
    return packet


def authenticationAndCipheringReject():
    """AUTHENTICATION AND CIPHERING REJECT Section 9.4.11"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x14)  # 00010100
    packet = a / b
    return packet


def identityRequest():
    """IDENTITY REQUEST Section 9.4.12"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x15)  # 00010101
    c = IdentityType2AndforceToStandby()
    packet = a / b / c
    return packet


def identityResponse():
    """IDENTITY RESPONSE Section 9.4.13"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x16)  # 00010110
    c = MobileId()
    packet = a / b / c
    return packet


def routingAreaUpdateRequest(PTmsiSignature_presence=0,
                             GprsTimer_presence=0,
                             DrxParameter_presence=0,
                             TmsiStatus_presence=0):
    """ROUTING AREA UPDATE REQUEST Section 9.4.14"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x8)  # 00001000
    c = UpdateTypeAndCiphKeySeqNr()
    e = RoutingAreaIdentification()
    f = MsNetworkCapability()
    packet = a / b / c / e / f
    if PTmsiSignature_presence is 1:
        g = PTmsiSignature(ieiPTS=0x19)
        packet = packet / g
    if GprsTimer_presence is 1:
        h = GprsTimer(ieiGT=0x17)
        packet = packet / h
    if DrxParameter_presence is 1:
        i = DrxParameter(ieiDP=0x27)
        packet = packet / i
    if TmsiStatus_presence is 1:
        j = TmsiStatus(ieiTS=0x9)
        packet = packet / j
    return packet


def routingAreaUpdateAccept(PTmsiSignature_presence=0,
                            MobileId_presence=0, MobileId_presence1=0,
                            ReceiveNpduNumbersList_presence=0,
                            GprsTimer_presence=0, GmmCause_presence=0):
    """ROUTING AREA UPDATE ACCEPT Section 9.4.15"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x9)  # 00001001
    c = ForceToStandbyAndUpdateResult()
    e = GprsTimer()
    f = RoutingAreaIdentification()
    packet = a / b / c / e / f
    if PTmsiSignature_presence is 1:
        g = PTmsiSignature(ieiPTS=0x19)
        packet = packet / g
    if MobileId_presence is 1:
        h = MobileIdHdr(ieiMI=0x18, eightBitMI=0x0)
        packet = packet / h
    if MobileId_presence1 is 1:
        i = MobileIdHdr(ieiMI=0x23, eightBitMI=0x0)
        packet = packet / i
    if ReceiveNpduNumbersList_presence is 1:
        j = ReceiveNpduNumbersList(ieiRNNL=0x26)
        packet = packet / j
    if GprsTimer_presence is 1:
        k = GprsTimer(ieiGT=0x17)
        packet = packet / k
    if GmmCause_presence is 1:
        l = GmmCause(ieiGC=0x25)
        packet = packet / l
    return packet


def routingAreaUpdateComplete(ReceiveNpduNumbersList_presence=0):
    """ROUTING AREA UPDATE COMPLETE Section 9.4.16"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0xa)  # 00001010
    packet = a / b
    if ReceiveNpduNumbersList_presence is 1:
        c = ReceiveNpduNumbersList(ieiRNNL=0x26)
        packet = packet / c
    return packet


def routingAreaUpdateReject():
    """ROUTING AREA UPDATE REJECT Section 9.4.17"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0xb)  # 00001011
    c = GmmCause()
    d = ForceToStandbyAndSpareHalfOctets()
    packet = a / b / c / d
    return packet


def gmmStatus():
    """GMM STATUS Section 9.4.18"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x20)  # 00100000
    c = GmmCause()
    packet = a / b / c
    return packet


def gmmInformation(NetworkName_presence=0, NetworkName_presence1=0,
                   TimeZone_presence=0, TimeZoneAndTime_presence=0,
                   LsaIdentifier_presence=0):
    """GMM INFORMATION Section 9.4.19"""
    a = TpPd(pd=0x3)
    b = MessageType(mesType=0x21)  # 00100001
    packet = a / b
    if NetworkName_presence is 1:
        c = NetworkNameHdr(ieiNN=0x43, eightBitNN=0x0)
        packet = packet / c
    if NetworkName_presence1 is 1:
        d = NetworkNameHdr(ieiNN=0x45, eightBitNN=0x0)
        packet = packet / d
    if TimeZone_presence is 1:
        e = TimeZoneHdr(ieiTZ=0x46, eightBitTZ=0x0)
        packet = packet / e
    if TimeZoneAndTime_presence is 1:
        f = TimeZoneAndTimeHdr(ieiTZAT=0x47, eightBitTZAT=0x0)
        packet = packet / f
    if LsaIdentifier_presence is 1:
        g = LsaIdentifierHdr(ieiLI=0x48, eightBitLI=0x0)
        packet = packet / g
    return packet

#
# 9.5 GPRS Session Management Messages
#


def activatePdpContextRequest(AccessPointName_presence=0,
                              ProtocolConfigurationOptions_presence=0):
    """ACTIVATE PDP CONTEXT REQUEST Section 9.5.1"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x41)  # 01000001
    c = NetworkServiceAccessPointIdentifier()
    d = LlcServiceAccessPointIdentifier()
    e = QualityOfService()
    f = PacketDataProtocolAddress()
    packet = a / b / c / d / e / f
    if AccessPointName_presence is 1:
        g = AccessPointName(ieiAPN=0x28)
        packet = packet / g
    if ProtocolConfigurationOptions_presence is 1:
        h = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / h
    return packet


def activatePdpContextAccept(PacketDataProtocolAddress_presence=0,
                             ProtocolConfigurationOptions_presence=0):
    """ACTIVATE PDP CONTEXT ACCEPT Section 9.5.2"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x42)  # 01000010
    c = LlcServiceAccessPointIdentifier()
    d = QualityOfService()
    e = RadioPriorityAndSpareHalfOctets()
    packet = a / b / c / d / e
    if PacketDataProtocolAddress_presence is 1:
        f = PacketDataProtocolAddress(ieiPDPA=0x2B)
        packet = packet / f
    if ProtocolConfigurationOptions_presence is 1:
        g = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / g
    return packet


def activatePdpContextReject(ProtocolConfigurationOptions_presence=0):
    """ACTIVATE PDP CONTEXT REJECT Section 9.5.3"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x43)  # 01000011
    c = SmCause()
    packet = a / b / c
    if ProtocolConfigurationOptions_presence is 1:
        d = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / d
    return packet


def requestPdpContextActivation(AccessPointName_presence=0):
    """REQUEST PDP CONTEXT ACTIVATION Section 9.5.4"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x44)  # 01000100
    c = PacketDataProtocolAddress()
    packet = a / b / c
    if AccessPointName_presence is 1:
        d = AccessPointName(ieiAPN=0x28)
        packet = packet / d
    return packet


def requestPdpContextActivationReject():
    """REQUEST PDP CONTEXT ACTIVATION REJECT Section 9.5.5"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x45)  # 01000101
    c = SmCause()
    packet = a / b / c
    return packet


def modifyPdpContextRequest():
    """MODIFY PDP CONTEXT REQUEST Section 9.5.6"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x48)  # 01001000
    c = RadioPriorityAndSpareHalfOctets()
    d = LlcServiceAccessPointIdentifier()
    e = QualityOfService()
    packet = a / b / c / d / e
    return packet


def modifyPdpContextAccept():
    """MODIFY PDP CONTEXT ACCEPT Section 9.5.7"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x45)  # 01000101
    packet = a / b
    return packet


def deactivatePdpContextRequest():
    """DEACTIVATE PDP CONTEXT REQUEST Section 9.5.8"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x46)  # 01000110
    c = SmCause()
    packet = a / b / c
    return packet


def deactivatePdpContextAccept():
    """DEACTIVATE PDP CONTEXT ACCEPT Section 9.5.9"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x47)  # 01000111
    packet = a / b
    return packet


def activateAaPdpContextRequest(AccessPointName_presence=0,
                                ProtocolConfigurationOptions_presence=0,
                                GprsTimer_presence=0):
    """ACTIVATE AA PDP CONTEXT REQUEST Section 9.5.10"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x50)  # 01010000
    c = NetworkServiceAccessPointIdentifier()
    d = LlcServiceAccessPointIdentifier()
    e = QualityOfService()
    f = PacketDataProtocolAddress()
    packet = a / b / c / d / e / f
    if AccessPointName_presence is 1:
        g = AccessPointName(ieiAPN=0x28)
        packet = packet / g
    if ProtocolConfigurationOptions_presence is 1:
        h = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / h
    if GprsTimer_presence is 1:
        i = GprsTimer(ieiGT=0x29)
        packet = packet / i
    return packet


def activateAaPdpContextAccept(ProtocolConfigurationOptions_presence=0,
                               GprsTimer_presence=0):
    """ACTIVATE AA PDP CONTEXT ACCEPT Section 9.5.11"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x51)  # 01010001
    c = LlcServiceAccessPointIdentifier()
    d = QualityOfService()
    e = MobileId()
    f = PacketDataProtocolAddress()
    g = RadioPriorityAndSpareHalfOctets()
    packet = a / b / c / d / e / f / g
    if ProtocolConfigurationOptions_presence is 1:
        i = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / i
    if GprsTimer_presence is 1:
        j = GprsTimer(ieiGT=0x29)
        packet = packet / j
    return packet


def activateAaPdpContextReject(ProtocolConfigurationOptions_presence=0):
    """ACTIVATE AA PDP CONTEXT REJECT Section 9.5.12"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x52)  # 01010010
    c = SmCause()
    packet = a / b / c
    if ProtocolConfigurationOptions_presence is 1:
        d = ProtocolConfigurationOptions(ieiPCO=0x27)
        packet = packet / d
    return packet


def deactivateAaPdpContextRequest():
    """DEACTIVATE AA PDP CONTEXT REQUEST Section 9.5.13"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x53)  # 01010011
    c = AaDeactivationCauseAndSpareHalfOctets()
    packet = a / b / c
    return packet


def deactivateAaPdpContextAccept():
    """DEACTIVATE AA PDP CONTEXT ACCEPT Section 9.5.14"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x54)  # 01010100
    packet = a / b
    return packet


def smStatus():
    """SM STATUS Section 9.5.15"""
    a = TpPd(pd=0x8)
    b = MessageType(mesType=0x55)  # 01010101
    c = SmCause()
    packet = a / b / c
    return packet


# ============================================#
# Information Elements contents (Section 10)  #
# =========================================== #

####
# This section contains the elements we need to build the messages
####

#
# Common information elements:
#
class CellIdentityHdr(Packet):
    """ Cell identity Section 10.5.1.1 """
    name = "Cell Identity"
    fields_desc = [
        BitField("eightBitCI", None, 1),
        XBitField("ieiCI", None, 7),
        ByteField("ciValue1", 0x0),
        ByteField("ciValue2", 0x0)
    ]


class CiphKeySeqNrHdr(Packet):
    """ Ciphering Key Sequence Number Section 10.5.1.2 """
    name = "Cipher Key Sequence Number"
    fields_desc = [
        XBitField("ieiCKSN", None, 4),
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3)
    ]


# Fix 1/2 len problem
class CiphKeySeqNrAndSpareHalfOctets(Packet):
    name = "Cipher Key Sequence Number and Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


# Fix 1/2 len problem
class CiphKeySeqNrAndMacModeAndChannelCodingRequest(Packet):
    name = "Cipher Key Sequence Number and Mac Mode And Channel Coding Request"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3),
        BitField("macMode", 0x0, 2),
        BitField("cs", 0x0, 2)
    ]


class LocalAreaIdHdr(Packet):
    """ Local Area Identification Section 10.5.1.3 """
    name = "Location Area Identification"
    fields_desc = [
        BitField("eightBitLAI", None, 1),
        XBitField("ieiLAI", None, 7),
        BitField("mccDigit2", 0x0, 4),
        BitField("mccDigit1", 0x0, 4),
        BitField("mncDigit3", 0x0, 4),
        BitField("mccDigit3", 0x0, 4),
        BitField("mncDigit2", 0x0, 4),
        BitField("mncDigit1", 0x0, 4),
        ByteField("lac1", 0x0),
        ByteField("lac2", 0x0)
    ]
#
# The Mobile Identity is a type 4 information element with a minimum
# length of 3 octet and 11 octets length maximal.
#


# len 3 - 11
class MobileIdHdr(Packet):
    """ Mobile Identity  Section 10.5.1.4 """
    name = "Mobile Identity"
    fields_desc = [
        BitField("eightBitMI", 0x0, 1),
        XBitField("ieiMI", 0x0, 7),

        XByteField("lengthMI", None),

        BitField("idDigit1", 0x0, 4),
        BitField("oddEven", 0x0, 1),
        BitField("typeOfId", 0x0, 3),
        # optional
    ] + list(itertools.chain(*[[
        BitField("idDigit%d_1" % x, None, 4),
        BitField("idDigit%d" % x, None, 4),
    ] for x in range(2, 10)]))

    def post_build(self, p, pay):
        # this list holds the values of the variables, the
        # INTERESTING value!
        a = [getattr(self, fld.name, None) for fld in self.fields_desc]
        res = _adapt(3, 11, a, self.fields_desc)
        if self.lengthMI is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MobileStationClassmark1Hdr(Packet):
    """ Mobile Station Classmark 1 Section 10.5.1.5 """
    name = "Mobile Station Classmark 1"
    fields_desc = [
        BitField("eightBitiMSC1", None, 1),
        XBitField("ieiMSC1", None, 7),
        BitField("spare", 0x0, 1),
        BitField("revisionLvl", 0x0, 2),
        BitField("esInd", 0x0, 1),
        BitField("a51", 0x0, 1),
        BitField("rfPowerCap", 0x0, 3)
    ]


class MobileStationClassmark2Hdr(Packet):
    """ Mobile Station Classmark 2 Section 10.5.1.6 """
    name = "Mobile Station Classmark 2"
    fields_desc = [
        BitField("eightBitMSC2", None, 1),
        XBitField("ieiMSC2", None, 7),
        XByteField("lengthMSC2", 0x3),
        BitField("spare", 0x0, 1),
        BitField("revisionLvl", 0x0, 2),
        BitField("esInd", 0x0, 1),
        BitField("a51", 0x0, 1),
        BitField("rfPowerCap", 0x0, 3),
        BitField("spare1", 0x0, 1),
        BitField("psCap", 0x0, 1),
        BitField("ssScreenInd", 0x0, 2),
        BitField("smCaPabi", 0x0, 1),
        BitField("vbs", 0x0, 1),
        BitField("vgcs", 0x0, 1),
        BitField("fc", 0x0, 1),
        BitField("cm3", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("lcsvaCap", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("soLsa", 0x0, 1),
        BitField("cmsp", 0x0, 1),
        BitField("a53", 0x0, 1),
        BitField("a52", 0x0, 1)
    ]


# len max 14
class MobileStationClassmark3(Packet):
    """ Mobile Station Classmark 3 Section 10.5.1.7 """
    name = "Mobile Station Classmark 3"
    fields_desc = [
        # FIXME
        ByteField("ieiMSC3", 0x0),
        ByteField("byte2", 0x0),
        ByteField("byte3", 0x0),
        ByteField("byte4", 0x0),
        ByteField("byte5", 0x0),
        ByteField("byte6", 0x0),
        ByteField("byte7", 0x0),
        ByteField("byte8", 0x0),
        ByteField("byte9", 0x0),
        ByteField("byte10", 0x0),
        ByteField("byte11", 0x0),
        ByteField("byte12", 0x0),
        ByteField("byte13", 0x0),
        ByteField("byte14", 0x0)
    ]


class SpareHalfOctets(Packet):
    """ Spare Half Octet Section 10.5.1.8 """
    name = "Spare Half Octet"
    fields_desc = [
        BitField("filler", None, 4),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class DescriptiveGroupOrBroadcastCallReferenceHdr(Packet):
    """ Descriptive group or broadcast call reference  Section 10.5.1.9 """
    name = "Descriptive Group or Broadcast Call Reference"
    fields_desc = [
        BitField("eightBitDGOBCR", None, 1),
        XBitField("ieiDGOBCR", None, 7),
        BitField("binCallRef", 0x0, 27),
        BitField("sf", 0x0, 1),
        BitField("fa", 0x0, 1),
        BitField("callPrio", 0x0, 3),
        BitField("cipherInfo", 0x0, 4),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("spare4", 0x0, 1)
    ]


class GroupCipherKeyNumber(Packet):
    """ Group Cipher Key Number reference  Section 10.5.1.10 """
    name = "Group Cipher Key Number"
    fields_desc = [
        XBitField("ieiGCKN", None, 4),
        BitField("groupCipher", 0x0, 4)
    ]


class PdAndSapiHdr(Packet):
    """ PD and SAPI $(CCBS)$  Section 10.5.1.10a """
    name = "PD and SAPI $(CCBS)$"
    fields_desc = [
        BitField("eightBitPAS", None, 1),
        XBitField("ieiPAS", None, 7),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("sapi", 0x0, 2),
        BitField("pd", 0x0, 4)
    ]


class PriorityLevelHdr(Packet):
    """ Priority Level Section 10.5.1.11 """
    name = "Priority Level"
    fields_desc = [
        XBitField("ieiPL", None, 4),
        BitField("spare", 0x0, 1),
        BitField("callPrio", 0x0, 3)
    ]

#
# Radio Resource management information elements
#


# len 6 to max for L3 message (251)
class BaRangeHdr(Packet):
    """ BA Range Section 10.5.2.1a """
    name = "BA Range"
    fields_desc = [
        BitField("eightBitBR", None, 1),
        XBitField("ieiBR", None, 7),

        XByteField("lengthBR", None),
        # error: byte format requires -128 <= number <= 127
        ByteField("nrOfRanges", 0x0),
        #              # rX = range X
        #              # L o = Lower H i = higher
        #              # H p = high Part Lp = low Part
        ByteField("r1LoHp", 0x0),
        BitField("r1LoLp", 0x0, 3),
        BitField("r1HiHp", 0x0, 5),
        BitField("r1HiLp", 0x0, 4),

        BitField("r2LoHp", 0x0, 4),
        # optional
        BitField("r2LoLp", None, 5),
        BitField("r2HiHp", None, 3),
        ByteField("r2HiLp", None),
    ] + list(itertools.chain(*[[
        ByteField("r%dLoHp" % x, None),
        BitField("r%dLoLp" % x, None, 5),
        BitField("r%dHiHp" % x, None, 3),
        ByteField("r%dHiLp" % x, None),
    ] for x in range(3, 85)]))

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(6, 251, a, self.fields_desc)
        if self.lengthBR is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 3 to max for L3 message (251)
class BaListPrefHdr(Packet):
    """ BA List Pref Section 10.5.2.1c """
    name = "BA List Pref"
    fields_desc = [
        # FIXME dynamic
        BitField("eightBitBLP", None, 1),
        XBitField("ieiBLP", None, 7),

        XByteField("lengthBLP", None),

        BitField("fixBit", 0x0, 1),
        BitField("rangeLower", 0x0, 10),
        BitField("fixBit2", 0x0, 1),
        BitField("rangeUpper", 0x0, 10),
        BitField("baFreq", 0x0, 10),
        BitField("sparePad", 0x0, 8)
    ]


# len 17 || Have a look at the specs for the field format
# Bit map 0 format
# Range 1024 format
# Range  512 format
# Range  256 format
# Range  128 format
# Variable bit map format
class CellChannelDescriptionHdr(Packet):
    """ Cell Channel Description  Section 10.5.2.1b """
    name = "Cell Channel Description "
    fields_desc = [
        BitField("eightBitCCD", None, 1),
        XBitField("ieiCCD", None, 7),
        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        ByteField("bit120", 0x0),
        ByteField("bit112", 0x0),
        ByteField("bit104", 0x0),
        ByteField("bit96", 0x0),
        ByteField("bit88", 0x0),
        ByteField("bit80", 0x0),
        ByteField("bit72", 0x0),
        ByteField("bit64", 0x0),
        ByteField("bit56", 0x0),
        ByteField("bit48", 0x0),
        ByteField("bit40", 0x0),
        ByteField("bit32", 0x0),
        ByteField("bit24", 0x0),
        ByteField("bit16", 0x0),
        ByteField("bit8", 0x0)
    ]


class CellDescriptionHdr(Packet):
    """ Cell Description  Section 10.5.2.2 """
    name = "Cell Description"
    fields_desc = [
        BitField("eightBitCD", None, 1),
        XBitField("ieiCD", None, 7),
        BitField("bcchHigh", 0x0, 2),
        BitField("ncc", 0x0, 3),
        BitField("bcc", 0x0, 3),
        ByteField("bcchLow", 0x0)
    ]


class CellOptionsBCCHHdr(Packet):
    """ Cell Options (BCCH)  Section 10.5.2.3 """
    name = "Cell Options (BCCH)"
    fields_desc = [
        BitField("eightBitCOB", None, 1),
        XBitField("ieiCOB", None, 7),
        BitField("spare", 0x0, 1),
        BitField("pwrc", 0x0, 1),
        BitField("dtx", 0x0, 2),
        BitField("rLinkTout", 0x0, 4)
    ]


class CellOptionsSACCHHdr(Packet):
    """ Cell Options (SACCH) Section 10.5.2.3a """
    name = "Cell Options (SACCH)"
    fields_desc = [
        BitField("eightBitCOS", None, 1),
        XBitField("ieiCOS", None, 7),
        BitField("dtx", 0x0, 1),
        BitField("pwrc", 0x0, 1),
        BitField("dtx", 0x0, 1),
        BitField("rLinkTout", 0x0, 4)
    ]


class CellSelectionParametersHdr(Packet):
    """ Cell Selection Parameters Section 10.5.2.4 """
    name = "Cell Selection Parameters"
    fields_desc = [
        BitField("eightBitCSP", None, 1),
        XBitField("ieiCSP", None, 7),
        BitField("cellReselect", 0x0, 3),
        BitField("msTxPwrMax", 0x0, 5),
        BitField("acs", None, 1),
        BitField("neci", None, 1),
        BitField("rxlenAccMin", None, 6)
    ]


class MacModeAndChannelCodingRequestHdr(Packet):
    """ MAC Mode and Channel Coding Requested Section 10.5.2.4a """
    name = "MAC Mode and Channel Coding Requested"
    fields_desc = [
        XBitField("ieiMMACCR", None, 4),
        BitField("macMode", 0x0, 2),
        BitField("cs", 0x0, 2)
    ]


class ChannelDescriptionHdr(Packet):
    """ Channel Description  Section 10.5.2.5 """
    name = "Channel Description"
    fields_desc = [
        BitField("eightBitCD", None, 1),
        XBitField("ieiCD", None, 7),

        BitField("channelTyp", 0x0, 5),
        BitField("tn", 0x0, 3),

        BitField("tsc", 0x0, 3),
        BitField("h", 0x1, 1),
        # if h=1 maybe we find a better solution here...
        BitField("maioHi", 0x0, 4),

        BitField("maioLo", 0x0, 2),
        BitField("hsn", 0x0, 6)
        #BitField("spare", 0x0, 2),
        #BitField("arfcnHigh", 0x0, 2),
        #ByteField("arfcnLow", 0x0)
    ]


class ChannelDescription2Hdr(Packet):
    """ Channel Description 2 Section 10.5.2.5a """
    name = "Channel Description 2"
    fields_desc = [
        BitField("eightBitCD2", None, 1),
        XBitField("ieiCD2", None, 7),
        BitField("channelTyp", 0x0, 5),
        BitField("tn", 0x0, 3),
        BitField("tsc", 0x0, 3),
        BitField("h", 0x0, 1),
        # if h=1
        # BitField("maioHi", 0x0, 4),
        # BitField("maioLo", 0x0, 2),
        # BitField("hsn", 0x0, 6)
        BitField("spare", 0x0, 2),
        BitField("arfcnHigh", 0x0, 2),
        ByteField("arfcnLow", 0x0)
    ]


class ChannelModeHdr(Packet):
    """ Channel Mode Section 10.5.2.6 """
    name = "Channel Mode"
    fields_desc = [
        BitField("eightBitCM", None, 1),
        XBitField("ieiCM", None, 7),
        ByteField("mode", 0x0)
    ]


class ChannelMode2Hdr(Packet):
    """ Channel Mode 2 Section 10.5.2.7 """
    name = "Channel Mode 2"
    fields_desc = [
        BitField("eightBitCM2", None, 1),
        XBitField("ieiCM2", None, 7),
        ByteField("mode", 0x0)
    ]


class ChannelNeededHdr(Packet):
    """ Channel Needed Section 10.5.2.8 """
    name = "Channel Needed"
    fields_desc = [
        XBitField("ieiCN", None, 4),
        BitField("channel2", 0x0, 2),
        BitField("channel1", 0x0, 2),
    ]


class ChannelRequestDescriptionHdr(Packet):
    """Channel Request Description  Section 10.5.2.8a """
    name = "Channel Request Description"
    fields_desc = [
        BitField("eightBitCRD", None, 1),
        XBitField("ieiCRD", None, 7),
        BitField("mt", 0x0, 1),
        ConditionalField(BitField("spare", 0x0, 39),
                         lambda pkt: pkt.mt == 0),
        ConditionalField(BitField("spare", 0x0, 3),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("priority", 0x0, 2),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("rlcMode", 0x0, 1),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("llcFrame", 0x1, 1),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("reqBandMsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("reqBandLsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("rlcMsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("rlcLsb", 0x0),
                         lambda pkt: pkt.mt == 1)
    ]


class CipherModeSettingHdr(Packet):
    """Cipher Mode Setting Section 10.5.2.9 """
    name = "Cipher Mode Setting"
    fields_desc = [
        XBitField("ieiCMS", None, 4),
        BitField("algoId", 0x0, 3),
        BitField("sc", 0x0, 1),
    ]


class CipherResponseHdr(Packet):
    """Cipher Response Section 10.5.2.10 """
    name = "Cipher Response"
    fields_desc = [
        XBitField("ieiCR", None, 4),
        BitField("spare", 0x0, 3),
        BitField("cr", 0x0, 1),
    ]


# This  packet fixes the problem with the 1/2 Byte length. Concatenation
# of cipherModeSetting and cipherResponse
class CipherModeSettingAndcipherResponse(Packet):
    name = "Cipher Mode Setting And Cipher Response"
    fields_desc = [
        BitField("algoId", 0x0, 3),
        BitField("sc", 0x0, 1),
        BitField("spare", 0x0, 3),
        BitField("cr", 0x0, 1)
    ]


class ControlChannelDescriptionHdr(Packet):
    """Control Channel Description Section 10.5.2.11 """
    name = "Control Channel Description"
    fields_desc = [
        BitField("eightBitCCD", None, 1),
        XBitField("ieiCCD", None, 7),

        BitField("spare", 0x0, 1),
        BitField("att", 0x0, 1),
        BitField("bsAgBlksRes", 0x0, 3),
        BitField("ccchConf", 0x0, 3),

        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("spare4", 0x0, 1),
        BitField("bsPaMfrms", 0x0, 3),

        ByteField("t3212", 0x0)
    ]


class FrequencyChannelSequenceHdr(Packet):
    """Frequency Channel Sequence Section 10.5.2.12"""
    name = "Frequency Channel Sequence"
    fields_desc = [
        BitField("eightBitFCS", None, 1),
        XBitField("ieiFCS", None, 7),
        BitField("spare", 0x0, 1),
        BitField("lowestArfcn", 0x0, 7),
    ] + [BitField("skipArfcn%02d" % x, 0x0, 4) for x in range(1, 17)]


class FrequencyListHdr(Packet):
    """Frequency List Section 10.5.2.13"""
    name = "Frequency List"
 # Problem:
 # There are several formats for the Frequency List information
 # element, distinguished by the "format indicator" subfield.
 # Some formats are frequency bit maps, the others use a special encoding
 # scheme.
    fields_desc = [
        BitField("eightBitFL", None, 1),
        XBitField("ieiFL", None, 7),
        XByteField("lengthFL", None),

        BitField("formatID", 0x0, 2),
        BitField("spare", 0x0, 2),
        BitField("arfcn124", 0x0, 1),
        BitField("arfcn123", 0x0, 1),
        BitField("arfcn122", 0x0, 1),
        BitField("arfcn121", 0x0, 1),

        ByteField("arfcn120", 0x0),
        ByteField("arfcn112", 0x0),
        ByteField("arfcn104", 0x0),
        ByteField("arfcn96", 0x0),
        ByteField("arfcn88", 0x0),
        ByteField("arfcn80", 0x0),
        ByteField("arfcn72", 0x0),
        ByteField("arfcn64", 0x0),
        ByteField("arfcn56", 0x0),
        ByteField("arfcn48", 0x0),
        ByteField("arfcn40", 0x0),
        ByteField("arfcn32", 0x0),
        ByteField("arfcn24", 0x0),
        ByteField("arfcn16", 0x0),
        ByteField("arfcn8", 0x0)
    ]


class FrequencyShortListHdr(Packet):
    """Frequency Short List Section 10.5.2.14"""
    name = "Frequency Short List"
# len is 10
# This element is encoded exactly as the Frequency List information element,
# except that it has a fixed length instead of a
# variable length and does not contain a length indicator and that it
# shall not be encoded in bitmap 0 format.
    fields_desc = [
        ByteField("ieiFSL", 0x0),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 11)]


class FrequencyShortListHdr2(Packet):
    """Frequency Short List2 Section 10.5.2.14a"""
    name = "Frequency Short List 2"
    fields_desc = [
        ByteField("byte%d" % x, 0x0) for x in range(1, 9)
    ]


# len 4 to 13
class GroupChannelDescriptionHdr(Packet):
    """Group Channel Description Section 10.5.2.14b"""
    name = "Group Channel Description"
    fields_desc = [
        BitField("eightBitGCD", None, 1),
        XBitField("ieiGCD", None, 7),

        XByteField("lengthGCD", None),

        BitField("channelType", 0x0, 5),
        BitField("tn", 0x0, 3),

        BitField("tsc", 0x0, 3),
        BitField("h", 0x0, 1),
        # if  h == 0 the  packet looks the following way:
        ConditionalField(BitField("spare", 0x0, 2),
                         lambda pkt: pkt. h == 0x0),
        ConditionalField(BitField("arfcnHi", 0x0, 2),
                         lambda pkt: pkt. h == 0x0),
        ConditionalField(ByteField("arfcnLo", None),
                         lambda pkt: pkt. h == 0x0),
        # if  h == 1 the  packet looks the following way:
        ConditionalField(BitField("maioHi", 0x0, 4),
                         lambda pkt: pkt. h == 0x1),
        ConditionalField(BitField("maioLo", None, 2),
                         lambda pkt: pkt. h == 0x1),
        ConditionalField(BitField("hsn", None, 6),
                         lambda pkt: pkt. h == 0x1),
        # finished with conditional fields
    ] + [ByteField("maC%d" % x, None) for x in range(6, 15)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 13, a, self.fields_desc)
        if self.lengthGCD is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class GprsResumptionHdr(Packet):
    """GPRS Resumption  Section 10.5.2.14c"""
    name = "GPRS Resumption"
    fields_desc = [
        XBitField("ieiGR", None, 4),
        BitField("spare", 0x0, 3),
        BitField("ack", 0x0, 1)
    ]


class HandoverReferenceHdr(Packet):
    """Handover Reference Section 10.5.2.15"""
    name = "Handover Reference"
    fields_desc = [
        BitField("eightBitHR", None, 1),
        XBitField("ieiHR", None, 7),
        ByteField("handoverRef", 0x0)
    ]


# len 1-12
class IaRestOctets(Packet):
    """IA Rest Octets Section 10.5.2.16"""
    name = "IA Rest Octets"
    fields_desc = [
        ByteField("ieiIRO", 0x0),
        # FIXME brainfuck  packet
        XByteField("lengthIRO", None),
    ] + [ByteField("spare%d", None) for x in range(2, 12)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 12, a, self.fields_desc)
        if self.lengthIRO is None:
            if res[1] < 0:  # FIXME better fix
                res[1] = 0
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class IraRestOctetsHdr(Packet):
    """IAR Rest Octets Section 10.5.2.17"""
    name = "IAR Rest Octets"
    fields_desc = [
        BitField("eightBitIRO", None, 1),
        XBitField("ieiIRO", None, 7),
    ] + [BitField("spare%02d", 0x1, 1) for x in range(1, 25)]


# len is 1 to 5 what do we do with the variable size? no length
# field?! WTF
class IaxRestOctetsHdr(Packet):
    """IAX Rest Octets Section 10.5.2.18"""
    name = "IAX Rest Octets"
    fields_desc = [
        BitField("eightBitIRO", None, 1),
        XBitField("ieiIRO", None, 7),
        BitField("spare01", 0x0, 1),
        BitField("spare02", 0x0, 1),
        BitField("spare03", 0x1, 1),
        BitField("spare04", 0x0, 1),
        BitField("spare05", 0x1, 1),
        BitField("spare06", 0x0, 1),
        BitField("spare07", 0x1, 1),
        BitField("spare08", 0x1, 1),
        ByteField("spareB1", None),
        ByteField("spareB2", None),
        ByteField("spareB3", None)
    ]


class L2PseudoLengthHdr(Packet):
    """L2 Pseudo Length Section 10.5.2.19"""
    name = "L2 Pseudo Length"
    fields_desc = [
        BitField("eightBitPL", None, 1),
        XBitField("ieiPL", None, 7),
        BitField("l2pLength", None, 6),
        BitField("bit2", 0x0, 1),
        BitField("bit1", 0x1, 1)
    ]


class MeasurementResultsHdr(Packet):
    """Measurement Results Section 10.5.2.20"""
    name = "Measurement Results"
    fields_desc = [
        BitField("eightBitMR", None, 1),
        XBitField("ieiMR", None, 7),
        BitField("baUsed", 0x0, 1),
        BitField("dtxUsed", 0x0, 1),
        BitField("rxLevFull", 0x0, 6),
        BitField("spare", 0x0, 1),
        BitField("measValid", 0x0, 1),
        BitField("rxLevSub", 0x0, 6),
        BitField("spare0", 0x0, 1),
        BitField("rxqualFull", 0x0, 3),
        BitField("rxqualSub", 0x0, 3),
        BitField("noNcellHi", 0x0, 1),
        BitField("noNcellLo", 0x0, 2),
        BitField("rxlevC1", 0x0, 6),
        BitField("bcchC1", 0x0, 5),
        BitField("bsicC1Hi", 0x0, 3),
        BitField("bsicC1Lo", 0x0, 3),
        BitField("rxlevC2", 0x0, 5),
        BitField("rxlevC2Lo", 0x0, 1),
        BitField("bcchC2", 0x0, 5),
        BitField("bsicC1Hi", 0x0, 2),
        BitField("bscicC2Lo", 0x0, 4),
        BitField("bscicC2Hi", 0x0, 4),

        BitField("rxlevC3Lo", 0x0, 2),
        BitField("bcchC3", 0x0, 5),
        BitField("rxlevC3Hi", 0x0, 1),

        BitField("bsicC3Lo", 0x0, 5),
        BitField("bsicC3Hi", 0x0, 3),

        BitField("rxlevC4Lo", 0x0, 3),
        BitField("bcchC4", 0x0, 5),

        BitField("bsicC4", 0x0, 6),
        BitField("rxlevC5Hi", 0x0, 2),

        BitField("rxlevC5Lo", 0x0, 4),
        BitField("bcchC5Hi", 0x0, 4),

        BitField("bcchC5Lo", 0x0, 1),
        BitField("bsicC5", 0x0, 6),
        BitField("rxlevC6", 0x0, 1),

        BitField("rxlevC6Lo", 0x0, 5),
        BitField("bcchC6Hi", 0x0, 3),

        BitField("bcchC6Lo", 0x0, 3),
        BitField("bsicC6", 0x0, 5)
    ]


class GprsMeasurementResultsHdr(Packet):
    """GPRS Measurement Results Section 10.5.2.20a"""
    name = "GPRS Measurement Results"
    fields_desc = [
        BitField("eightBitGMR", None, 1),
        XBitField("ieiGMR", None, 7),
        BitField("cValue", 0x0, 6),
        BitField("rxqualHi", 0x0, 2),
        BitField("rxqL", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("signVar", 0x0, 6)
    ]


# len 3 to 10
class MobileAllocationHdr(Packet):
    """Mobile Allocation Section 10.5.2.21"""
    name = "Mobile Allocation"
    fields_desc = [
        BitField("eightBitMA", None, 1),
        XBitField("ieiMA", None, 7),
        XByteField("lengthMA", None),
        ByteField("maC64", 0x12),
        ByteField("maC56", None),  # optional fields start here
        ByteField("maC48", None),
        ByteField("maC40", None),
        ByteField("maC32", None),
        ByteField("maC24", None),
        ByteField("maC16", None),
        ByteField("maC8", None)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 10, a, self.fields_desc)
        if self.lengthMA is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MobileTimeDifferenceHdr(Packet):
    """Mobile Time Difference Section 10.5.2.21a"""
    name = "Mobile Time Difference"
    fields_desc = [
        BitField("eightBitMTD", None, 1),
        XBitField("ieiMTD", None, 7),
        XByteField("lengthMTD", 0x5),
        ByteField("valueHi", 0x0),
        ByteField("valueCnt", 0x0),
        BitField("valueLow", 0x0, 5),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1)
    ]


# min 4 octets max 8
class MultiRateConfigurationHdr(Packet):
    """ MultiRate configuration Section 10.5.2.21aa"""
    name = "MultiRate Configuration"
    fields_desc = [
        BitField("eightBitMRC", None, 1),
        XBitField("ieiMRC", None, 7),

        XByteField("lengthMRC", None),

        BitField("mrVersion", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("icmi", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("startMode", 0x0, 2),

        ByteField("amrCodec", 0x0),

        BitField("spare", None, 2),
        BitField("threshold1", None, 6),

        BitField("hysteresis1", None, 4),
        BitField("threshold2", None, 4),

        BitField("threshold2cnt", None, 2),
        BitField("hysteresis2", None, 4),
        BitField("threshold3", None, 2),

        BitField("threshold3cnt", None, 4),
        BitField("hysteresis3", None, 4)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 8, a, self.fields_desc)
        if self.lengthMRC is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 3 to 12
class MultislotAllocationHdr(Packet):
    """Multislot Allocation Section 10.5.2.21b"""
    name = "Multislot Allocation"
    fields_desc = [
        BitField("eightBitMSA", None, 1),
        XBitField("ieiMSA", None, 7),
        XByteField("lengthMSA", None),
        BitField("ext0", 0x1, 1),
        BitField("da", 0x0, 7),
        ConditionalField(BitField("ext1", 0x1, 1),  # optional
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("ua", 0x0, 7),
                         lambda pkt: pkt.ext0 == 0),
    ] + [ByteField("chan%d" % x, None) for x in range(1, 9)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 12, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthMSA is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


class NcModeHdr(Packet):
    """NC mode Section 10.5.2.21c"""
    name = "NC Mode"
    fields_desc = [
        XBitField("ieiNM", None, 4),
        BitField("spare", 0x0, 2),
        BitField("ncMode", 0x0, 2)
    ]


# Fix for len problem
# concatenation NC Mode And Spare Half Octets
class NcModeAndSpareHalfOctets(Packet):
    name = "NC Mode And Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x0, 2),
        BitField("ncMode", 0x0, 2),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class NeighbourCellsDescriptionHdr(Packet):
    """Neighbour Cells Description Section 10.5.2.22"""
    name = "Neighbour Cells Description"
    fields_desc = [
        BitField("eightBitNCD", None, 1),
        XBitField("ieiNCD", None, 7),
        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("extInd", 0x0, 1),
        BitField("baInd", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        BitField("120bits", 0x0, 120)
    ]


class NeighbourCellsDescription2Hdr(Packet):
    """Neighbour Cells Description 2 Section 10.5.2.22a"""
    name = "Neighbour Cells Description 2"
    fields_desc = [
        BitField("eightBitNCD2", None, 1),
        XBitField("ieiNCD2", None, 7),
        BitField("bit128", 0x0, 1),
        BitField("multiband", 0x0, 2),
        BitField("baInd", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        BitField("120bits", 0x0, 120)
    ]


class NtNRestOctets(Packet):
    """NT/N Rest Octets Section 10.5.2.22c"""
    name = "NT/N Rest Octets"
    fields_desc = [
        BitField("nln", 0x0, 2),
        BitField("ncnInfo", 0x0, 4),
        BitField("spare", 0x0, 2)
    ]


#
# The following  packet has no length info!
#
# len 1-18
class P1RestOctets(Packet):
    """P1 Rest Octets Section 10.5.2.23"""
    name = "P1 Rest Octets"
    fields_desc = [
        BitField("nln", 0x0, 2),
        BitField("nlnStatus", 0x0, 1),
        BitField("prio1", 0x0, 3),
        BitField("prio2", 0x0, 3),
        # optional
        BitField("pageIndication1", 0x0, 1),
        BitField("pageIndication2", 0x0, 1),
        BitField("spare", 0x0, 5),
    ] + [ByteField("spareB%d" % x, None) for x in range(1, 17)]


# len 2-12
class P2RestOctets(Packet):
    """P2 Rest Octets Section 10.5.2.24"""
    name = "P2 Rest Octets"
    fields_desc = [
        BitField("cn3", 0x0, 2),
        BitField("nln", 0x0, 2),
        BitField("nlnStatus", 0x0, 1),
        BitField("prio1", 0x0, 3),

        BitField("prio2", 0x0, 3),
        BitField("prio3", 0x0, 3),
        BitField("pageIndication3", 0x0, 1),
        BitField("spare", 0x0, 1),

        # optinal (No length field!)
    ] + [ByteField("spareB%d" % x, None) for x in range(1, 11)]


# len 4
class P3RestOctets(Packet):
    """P3 Rest Octets Section 10.5.2.25"""
    name = "P3 Rest Octets"
    fields_desc = [
        BitField("cn3", 0x0, 2),
        BitField("cn4", 0x0, 2),
        BitField("nln", 0x0, 2),
        BitField("nlnStatus", 0x0, 1),
        BitField("prio1", 0x0, 3),
        BitField("prio2", 0x0, 3),
        BitField("prio3", 0x0, 3),
        BitField("prio4", 0x0, 3),
        BitField("spare", 0x0, 5)
    ]


# len 4
# strange  packet, lots of valid formats

# ideas for the dynamic  packets:
# 1] for user interaction: Create an interactive "builder" based on a
# Q/A process (not very scapy like)
# 2] for usage in scripts, create an alternative  packet for every
# possible  packet layout
#


class PacketChannelDescription(Packet):
    """Packet Channel Description Section 10.5.2.25a"""
    name = "Packet Channel Description"
    fields_desc = [
        ByteField("ieiPCD", None),
        BitField("chanType", 0x0, 5),  # This  packet has multiple
        # possible layouts. I moddeled the first one
        BitField("tn", 0x0, 3),     # maybe build an
        #"interactive" builder. Like
        # a Q/A then propose a
        #  packet?
        BitField("tsc", 0x0, 3),
        BitField("chooser1", 0x0, 1),
        BitField("chooser2", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("arfcn", 0x0, 10),
    ]


class DedicatedModeOrTBFHdr(Packet):
    """Dedicated mode or TBF Section 10.5.2.25b"""
    name = "Dedicated Mode or TBF"
    fields_desc = [
        XBitField("ieiDMOT", None, 4),
        BitField("spare", 0x0, 1),
        BitField("tma", 0x0, 1),
        BitField("downlink", 0x0, 1),
        BitField("td", 0x0, 1)
    ]


# FIXME add implementation
class RrPacketUplinkAssignment(Packet):
    """RR Packet Uplink Assignment Section 10.5.2.25c"""
    name = "RR Packet Uplink Assignment"
    fields_desc = [
        # Fill me
    ]


class PageModeHdr(Packet):
    """Page Mode Section 10.5.2.26"""
    name = "Page Mode"
    fields_desc = [
        XBitField("ieiPM", None, 4),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("pm", 0x0, 2)
    ]


# Fix for 1/2 len problem
# concatenation: pageMode and dedicatedModeOrTBF
class PageModeAndDedicatedModeOrTBF(Packet):
    name = "Page Mode and Dedicated Mode Or TBF"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("pm", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("tma", 0x0, 1),
        BitField("downlink", 0x0, 1),
        BitField("td", 0x0, 1)
    ]


# Fix for 1/2 len problem
# concatenation: pageMode and spareHalfOctets
class PageModeAndSpareHalfOctets(Packet):
    name = "Page Mode and Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("pm", 0x0, 2),
        BitField("spareHalfOctets", 0x0, 4)
    ]


# Fix for 1/2 len problem
# concatenation: pageMode and Channel Needed
class PageModeAndChannelNeeded(Packet):
    name = "Page Mode and Channel Needed"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("pm", 0x0, 2),
        BitField("channel2", 0x0, 2),
        BitField("channel1", 0x0, 2)
    ]


class NccPermittedHdr(Packet):
    """NCC Permitted Section 10.5.2.27"""
    name = "NCC Permitted"
    fields_desc = [
        BitField("eightBitNP", None, 1),
        XBitField("ieiNP", None, 7),
        ByteField("nccPerm", 0x0)
    ]


class PowerCommandHdr(Packet):
    """Power Command Section 10.5.2.28"""
    name = "Power Command"
    fields_desc = [
        BitField("eightBitPC", None, 1),
        XBitField("ieiPC", None, 7),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("powerLvl", 0x0, 5)
    ]


class PowerCommandAndAccessTypeHdr(Packet):
    """Power Command and access type  Section 10.5.2.28a"""
    name = "Power Command and Access Type"
    fields_desc = [
        BitField("eightBitPCAAT", None, 1),
        XBitField("ieiPCAAT", None, 7),
        BitField("atc", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("powerLvl", 0x0, 5)
    ]


class RachControlParametersHdr(Packet):
    """RACH Control Parameters Section 10.5.2.29"""
    name = "RACH Control Parameters"
    fields_desc = [
        BitField("eightBitRCP", None, 1),
        XBitField("ieiRCP", None, 7),
        BitField("maxRetrans", 0x0, 2),
        BitField("txInteger", 0x0, 4),
        BitField("cellBarrAccess", 0x0, 1),
        BitField("re", 0x0, 1),
    ] + [BitField("ACC" + "%02d" % x, 0x0, 1) for x in range(15, -1, -1)]


class RequestReferenceHdr(Packet):
    """Request Reference  Section 10.5.2.30"""
    name = "Request Reference"
    fields_desc = [
        BitField("eightBitRR", None, 1),
        XBitField("ieiRR", None, 7),
        ByteField("ra", 0x0),
        BitField("t1", 0x0, 5),
        BitField("t3Hi", 0x0, 3),
        BitField("t3Lo", 0x0, 3),
        BitField("t2", 0x0, 5)
    ]


class RrCauseHdr(Packet):
    """RR Cause  Section 10.5.2.31"""
    name = "RR Cause"
    fields_desc = [
        BitField("eightBitRC", None, 1),
        XBitField("ieiRC", None, 7),
        ByteField("rrCause", 0x0)
    ]


class Si1RestOctets(Packet):
    """SI 1 Rest Octets Section 10.5.2.32"""
    name = "SI 1 Rest Octets"
    fields_desc = [
        ByteField("nchPos", 0x0)
    ]


class Si2bisRestOctets(Packet):
    """SI 2bis Rest Octets Section 10.5.2.33"""
    name = "SI 2bis Rest Octets"
    fields_desc = [
        ByteField("spare", 0x0)
    ]


class Si2terRestOctets(Packet):
    """SI 2ter Rest Octets Section 10.5.2.33a"""
    name = "SI 2ter Rest Octets"
    fields_desc = [
        ByteField("spare%d" % x, 0x0) for x in range(1, 5)
    ]


# len 5
class Si3RestOctets(Packet):
    """SI 3 Rest Octets Section 10.5.2.34"""
    name = "SI 3 Rest Octets"
    fields_desc = [
        ByteField("byte1", 0x0),
        ByteField("byte2", 0x0),
        ByteField("byte3", 0x0),
        ByteField("byte4", 0x0),
        ByteField("byte5", 0x0)
    ]


# len 1 to 11
class Si4RestOctets(Packet):
    """SI 4 Rest Octets Section 10.5.2.35"""
    name = "SI 4 Rest Octets"
    fields_desc = [
        XByteField("lengthSI4", None),
    ] + [ByteField("byte%d" % x, None) for x in range(2, 12)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 11, a, self.fields_desc, 1)
        if self.lengthSI4 is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        if len(p) is 1:  # length of this packet can be 0, but packet is
            p = ''       # but the IE is manadatory 0_o
        return p + pay


class Si6RestOctets(Packet):
    """SI 6 Rest Octets Section 10.5.2.35a"""
    name = "SI 4 Rest Octets"
    fields_desc = [
        # FIXME
    ]


# len 21
class Si7RestOctets(Packet):
    """SI 7 Rest Octets Section 10.5.2.36"""
    name = "SI 7 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI7", 0x15),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 22)]


# len 21
class Si8RestOctets(Packet):
    """SI 8 Rest Octets Section 10.5.2.37"""
    name = "SI 8 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI8", 0x15),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 22)]


# len 17
class Si9RestOctets(Packet):
    """SI 9 Rest Octets Section 10.5.2.37a"""
    name = "SI 9 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI9", 0x11),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 18)]


# len 21
class Si13RestOctets(Packet):
    """SI 13 Rest Octets Section 10.5.2.37b"""
    name = "SI 13 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI3", 0x15),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 22)]


# 10.5.2.37c [spare]
# 10.5.2.37d [spare]


# len 21
class Si16RestOctets(Packet):
    """SI 16 Rest Octets Section 10.5.2.37e"""
    name = "SI 16 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI16", 0x15),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 22)]


# len 21
class Si17RestOctets(Packet):
    """SI 17 Rest Octets Section 10.5.2.37f"""
    name = "SI 17 Rest Octets"
    fields_desc = [
        # FIXME
        XByteField("lengthSI17", 0x15),
    ] + [ByteField("byte%d" % x, 0x0) for x in range(2, 22)]


class StartingTimeHdr(Packet):
    """Starting Time Section 10.5.2.38"""
    name = "Starting Time"
    fields_desc = [
        BitField("eightBitST", None, 1),
        XBitField("ieiST", None, 7),
        ByteField("ra", 0x0),
        BitField("t1", 0x0, 5),
        BitField("t3Hi", 0x0, 3),
        BitField("t3Lo", 0x0, 3),
        BitField("t2", 0x0, 5)
    ]


class SynchronizationIndicationHdr(Packet):
    """Synchronization Indication Section 10.5.2.39"""
    name = "Synchronization Indication"
    fields_desc = [
        XBitField("ieiSI", None, 4),
        BitField("nci", 0x0, 1),
        BitField("rot", 0x0, 1),
        BitField("si", 0x0, 2)
    ]


class TimingAdvanceHdr(Packet):
    """Timing Advance Section 10.5.2.40"""
    name = "Timing Advance"
    fields_desc = [
        BitField("eightBitTA", None, 1),
        XBitField("ieiTA", None, 7),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("timingVal", 0x0, 6)
    ]


class TimeDifferenceHdr(Packet):
    """ Time Difference Section 10.5.2.41"""
    name = "Time Difference"
    fields_desc = [
        BitField("eightBitTD", None, 1),
        XBitField("ieiTD", None, 7),
        XByteField("lengthTD", 0x3),
        ByteField("timeValue", 0x0)
    ]


class TlliHdr(Packet):
    """ TLLI Section Section 10.5.2.41a"""
    name = "TLLI"
    fields_desc = [
        BitField("eightBitT", None, 1),
        XBitField("ieiT", None, 7),
        ByteField("value", 0x0),
        ByteField("value1", 0x0),
        ByteField("value2", 0x0),
        ByteField("value3", 0x0)
    ]


class TmsiPTmsiHdr(Packet):
    """ TMSI/P-TMSI Section 10.5.2.42"""
    name = "TMSI/P-TMSI"
    fields_desc = [
        BitField("eightBitTPT", None, 1),
        XBitField("ieiTPT", None, 7),
        ByteField("value", 0x0),
        ByteField("value1", 0x0),
        ByteField("value2", 0x0),
        ByteField("value3", 0x0)
    ]


class VgcsTargetModeIdenticationHdr(Packet):
    """ VGCS target Mode Indication 10.5.2.42a"""
    name = "VGCS Target Mode Indication"
    fields_desc = [
        BitField("eightBitVTMI", None, 1),
        XBitField("ieiVTMI", None, 7),
        XByteField("lengthVTMI", 0x2),
        BitField("targerMode", 0x0, 2),
        BitField("cipherKeyNb", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1)
    ]


class WaitIndicationHdr(Packet):
    """ Wait Indication Section 10.5.2.43"""
    name = "Wait Indication"
    fields_desc = [  # asciiart of specs strange
        BitField("eightBitWI", None, 1),
        XBitField("ieiWI", None, 7),
        ByteField("timeoutVal", 0x0)
    ]


# len 17
class ExtendedMeasurementResultsHdr(Packet):
    """EXTENDED MEASUREMENT RESULTS Section 10.5.2.45"""
    name = "Extended Measurement Results"
    fields_desc = [
        BitField("eightBitEMR", None, 1),
        XBitField("ieiEMR", None, 7),

        BitField("scUsed", None, 1),
        BitField("dtxUsed", None, 1),
        BitField("rxLevC0", None, 6),

        BitField("rxLevC1", None, 6),
        BitField("rxLevC2Hi", None, 2),

        BitField("rxLevC2Lo", None, 4),
        BitField("rxLevC3Hi", None, 4),

        BitField("rxLevC3Lo", None, 3),
        BitField("rxLevC4", None, 5),

        BitField("rxLevC5", None, 6),
        BitField("rxLevC6Hi", None, 2),

        BitField("rxLevC6Lo", None, 4),
        BitField("rxLevC7Hi", None, 4),

        BitField("rxLevC7Lo", None, 2),
        BitField("rxLevC8", None, 6),

        BitField("rxLevC9", None, 6),
        BitField("rxLevC10Hi", None, 2),

        BitField("rxLevC10Lo", None, 4),
        BitField("rxLevC11Hi", None, 4),

        BitField("rxLevC13Lo", None, 2),
        BitField("rxLevC12", None, 6),

        BitField("rxLevC13", None, 6),
        BitField("rxLevC14Hi", None, 2),

        BitField("rxLevC14Lo", None, 4),
        BitField("rxLevC15Hi", None, 4),

        BitField("rxLevC15Lo", None, 2),
        BitField("rxLevC16", None, 6),


        BitField("rxLevC17", None, 6),
        BitField("rxLevC18Hi", None, 2),

        BitField("rxLevC18Lo", None, 4),
        BitField("rxLevC19Hi", None, 4),

        BitField("rxLevC19Lo", None, 2),
        BitField("rxLevC20", None, 6)
    ]


# len 17
class ExtendedMeasurementFrequencyListHdr(Packet):
    """Extended Measurement Frequency List Section 10.5.2.46"""
    name = "Extended Measurement Frequency List"
    fields_desc = [
        BitField("eightBitEMFL", None, 1),
        XBitField("ieiEMFL", None, 7),

        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("seqCode", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),

        BitField("bitsRest", 0x0, 128)
    ]


class SuspensionCauseHdr(Packet):
    """Suspension Cause Section 10.5.2.47"""
    name = "Suspension Cause"
    fields_desc = [
        BitField("eightBitSC", None, 1),
        XBitField("ieiSC", None, 7),
        ByteField("suspVal", 0x0)
    ]


class ApduIDHdr(Packet):
    """APDU Flags Section 10.5.2.48"""
    name = "Apdu Id"
    fields_desc = [
        XBitField("ieiAI", None, 4),
        BitField("id", None, 4)
    ]


class ApduFlagsHdr(Packet):
    """APDU Flags Section 10.5.2.49"""
    name = "Apdu Flags"
    fields_desc = [
        XBitField("iei", None, 4),
        BitField("spare", 0x0, 1),
        BitField("cr", 0x0, 1),
        BitField("firstSeg", 0x0, 1),
        BitField("lastSeg", 0x0, 1)
    ]


# Fix 1/2 len problem
class ApduIDAndApduFlags(Packet):
    name = "Apu Id and Apdu Flags"
    fields_desc = [
        BitField("id", None, 4),
        BitField("spare", 0x0, 1),
        BitField("cr", 0x0, 1),
        BitField("firstSeg", 0x0, 1),
        BitField("lastSeg", 0x0, 1)
    ]


# len 2 to max L3 (251) (done)
class ApduDataHdr(Packet):
    """APDU Data Section 10.5.2.50"""
    name = "Apdu Data"
    fields_desc = [
        BitField("eightBitAD", None, 1),
        XBitField("ieiAD", None, 7),
        XByteField("lengthAD", None),
        # optional
    ] + [ByteField("apuInfo%d" % x, None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 251, a, self.fields_desc)
        if self.lengthAD is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay

#
# 10.5.3 Mobility management information elements
#


class AuthenticationParameterRAND(Packet):
    """Authentication parameter RAND Section 10.5.3.1"""
    name = "Authentication Parameter Rand"
    fields_desc = [
        ByteField("ieiAPR", None),
        BitField("randValue", 0x0, 128)
    ]


class AuthenticationParameterSRES(Packet):
    """Authentication parameter SRES Section 10.5.3.2"""
    name = "Authentication Parameter Sres"
    fields_desc = [
        ByteField("ieiAPS", None),
        BitField("sresValue", 0x0, 40)
    ]


class CmServiceType(Packet):
    """CM service type Section 10.5.3.3"""
    name = "CM Service Type"
    fields_desc = [
        XBitField("ieiCST", 0x0, 4),
        BitField("serviceType", 0x0, 4)
    ]


class CmServiceTypeAndCiphKeySeqNr(Packet):
    name = "CM Service Type and Cipher Key Sequence Number"
    fields_desc = [
        BitField("keySeq", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("serviceType", 0x0, 4)
    ]


class IdentityType(Packet):
    """Identity type Section 10.5.3.4"""
    name = "Identity Type"
    fields_desc = [
        XBitField("ieiIT", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("idType", 0x1, 3)
    ]


# Fix 1/2 len problem
class IdentityTypeAndSpareHalfOctet(Packet):
    name = "Identity Type and Spare Half Octet"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("idType", 0x1, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class LocationUpdatingType(Packet):
    """Location updating type  Section 10.5.3.5"""
    name = "Location Updating Type"
    fields_desc = [
        XBitField("ieiLUT", 0x0, 4),
        BitField("for", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("lut", 0x0, 2)
    ]


class LocationUpdatingTypeAndCiphKeySeqNr(Packet):
    name = "Location Updating Type and Cipher Key Sequence Number"
    fields_desc = [
        BitField("for", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("lut", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3)
    ]


# len 3 to L3 max (251) (done)
class NetworkNameHdr(Packet):
    """Network Name Section 10.5.3.5a"""
    name = "Network Name"
    fields_desc = [
        BitField("eightBitNN", None, 1),
        XBitField("ieiNN", None, 7),

        XByteField("lengthNN", None),

        BitField("ext1", 0x1, 1),
        BitField("codingScheme", 0x0, 3),
        BitField("addCi", 0x0, 1),
        BitField("nbSpare", 0x0, 3),
        # optional
    ] + [ByteField("txtString%d" % x, None) for x in range(1, 249)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 251, a, self.fields_desc)
        if self.lengthNN is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class RejectCause(Packet):
    """Reject cause Section 10.5.3.6"""
    name = "Reject Cause"
    fields_desc = [
        ByteField("ieiRC", 0x0),
        ByteField("rejCause", 0x0)
    ]


class FollowOnProceed(Packet):
    """Follow-on Proceed Section 10.5.3.7"""
    name = "Follow-on Proceed"
    fields_desc = [
        ByteField("ieiFOP", 0x0),
    ]


class TimeZoneHdr(Packet):
    """Time Zone  Section 10.5.3.8"""
    name = "Time Zone"
    fields_desc = [
        BitField("eightBitTZ", None, 1),
        XBitField("ieiTZ", None, 7),
        ByteField("timeZone", 0x0),
    ]


class TimeZoneAndTimeHdr(Packet):
    """Time Zone and Time Section 10.5.3.9"""
    name = "Time Zone and Time"
    fields_desc = [
        BitField("eightBitTZAT", None, 1),
        XBitField("ieiTZAT", None, 7),
        ByteField("year", 0x0),
        ByteField("month", 0x0),
        ByteField("day", 0x0),
        ByteField("hour", 0x0),
        ByteField("minute", 0x0),
        ByteField("second", 0x0),
        ByteField("timeZone", 0x0)
    ]


class CtsPermissionHdr(Packet):
    """CTS permission Section 10.5.3.10"""
    name = "Cts Permission"
    fields_desc = [
        BitField("eightBitCP", None, 1),
        XBitField("ieiCP", None, 7),
    ]


class LsaIdentifierHdr(Packet):
    """LSA Identifier Section 10.5.3.11"""
    name = "Lsa Identifier"
    fields_desc = [
        BitField("eightBitLI", None, 1),
        XBitField("ieiLI", None, 7),
        ByteField("lsaID", 0x0),
        ByteField("lsaID1", 0x0),
        ByteField("lsaID2", 0x0)
    ]


#
# 10.5.4 Call control information elements
#

# 10.5.4.1 Extensions of codesets
# This is only text and no  packet

class LockingShiftProcedureHdr(Packet):
    """Locking shift procedure Section 10.5.4.2"""
    name = "Locking Shift Procedure"
    fields_desc = [
        XBitField("ieiLSP", None, 4),
        BitField("lockShift", 0x0, 1),
        BitField("codesetId", 0x0, 3)
    ]


class NonLockingShiftProcedureHdr(Packet):
    """Non-locking shift procedure Section 10.5.4.3"""
    name = "Non-locking Shift Procedure"
    fields_desc = [
        XBitField("ieiNLSP", None, 4),
        BitField("nonLockShift", 0x1, 1),
        BitField("codesetId", 0x0, 3)
    ]


class AuxiliaryStatesHdr(Packet):
    """Auxiliary states Section 10.5.4.4"""
    name = "Auxiliary States"
    fields_desc = [
        BitField("eightBitAS", None, 1),
        XBitField("ieiAS", None, 7),
        XByteField("lengthAS", 0x3),
        BitField("ext", 0x1, 1),
        BitField("spare", 0x0, 3),
        BitField("holdState", 0x0, 2),
        BitField("mptyState", 0x0, 2)
    ]


# len 3 to 15
class BearerCapabilityHdr(Packet):
    """Bearer capability Section 10.5.4.5"""
    name = "Bearer Capability"
    fields_desc = [
        BitField("eightBitBC", None, 1),
        XBitField("ieiBC", None, 7),

        XByteField("lengthBC", None),

        BitField("ext0", 0x1, 1),
        BitField("radioChReq", 0x1, 2),
        BitField("codingStd", 0x0, 1),
        BitField("transMode", 0x0, 1),
        BitField("infoTransCa", 0x0, 3),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("coding", None, 1),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("spare", None, 2),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("speechVers", 0x0, 4),
                         lambda pkt: pkt.ext0 == 0),

        ConditionalField(BitField("ext2", 0x1, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("compress", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("structure", None, 2),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("dupMode", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("config", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("nirr", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("establi", 0x0, 1),
                         lambda pkt: pkt.ext1 == 0),

        BitField("ext3", None, 1),
        BitField("accessId", None, 2),
        BitField("rateAda", None, 2),
        BitField("signaling", None, 3),

        ConditionalField(BitField("ext4", None, 1),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("otherITC", None, 2),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("otherRate", None, 2),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("spare1", 0x0, 3),
                         lambda pkt: pkt.ext3 == 0),

        ConditionalField(BitField("ext5", 0x1, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("hdr", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("multiFr", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("mode", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("lli", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("assig", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("inbNeg", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("spare2", 0x0, 1),
                         lambda pkt: pkt.ext4 == 0),

        BitField("ext6", None, 1),
        BitField("layer1Id", None, 2),
        BitField("userInf", None, 4),
        BitField("sync", None, 1),

        ConditionalField(BitField("ext7", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("stopBit", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("negoc", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("nbDataBit", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("userRate", None, 4),
                         lambda pkt: pkt.ext6 == 0),

        ConditionalField(BitField("ext8", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("interRate", None, 2),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("nicTX", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("nicRX", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("parity", None, 3),
                         lambda pkt: pkt.ext7 == 0),

        ConditionalField(BitField("ext9", None, 1),
                         lambda pkt: pkt.ext8 == 0),
        ConditionalField(BitField("connEle", None, 2),
                         lambda pkt: pkt.ext8 == 0),
        ConditionalField(BitField("modemType", None, 5),
                         lambda pkt: pkt.ext8 == 0),

        ConditionalField(BitField("ext10", None, 1),
                         lambda pkt: pkt.ext9 == 0),
        ConditionalField(BitField("otherModemType", None, 2),
                         lambda pkt: pkt.ext9 == 0),
        ConditionalField(BitField("netUserRate", None, 5),
                         lambda pkt: pkt.ext9 == 0),

        ConditionalField(BitField("ext11", None, 1),
                         lambda pkt: pkt.ext10 == 0),
        ConditionalField(BitField("chanCoding", None, 4),
                         lambda pkt: pkt.ext10 == 0),
        ConditionalField(BitField("maxTrafficChan", None, 3),
                         lambda pkt: pkt.ext10 == 0),

        ConditionalField(BitField("ext12", None, 1),
                         lambda pkt: pkt.ext11 == 0),
        ConditionalField(BitField("uimi", None, 3),
                         lambda pkt: pkt.ext11 == 0),
        ConditionalField(BitField("airInterfaceUserRate", None, 4),
                         lambda pkt: pkt.ext11 == 0),

        ConditionalField(BitField("ext13", 0x1, 1),
                         lambda pkt: pkt.ext12 == 0),
        ConditionalField(BitField("layer2Ch", None, 2),
                         lambda pkt: pkt.ext12 == 0),
        ConditionalField(BitField("userInfoL2", 0x0, 5),
                         lambda pkt: pkt.ext12 == 0)
    ]

    # We have a bug here. packet is not working if used in message
    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 15, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        # avoids a bug. find better way
        if len(p) is 5:
            p = p[:-2]
        if self.lengthBC is None:
            p = p[:1] + chb(len(p) - 3) + p[2:]
        return p + pay


class CallControlCapabilitiesHdr(Packet):
    """Call Control Capabilities Section 10.5.4.5a"""
    name = "Call Control Capabilities"
    fields_desc = [
        BitField("eightBitCCC", None, 1),
        XBitField("ieiCCC", None, 7),
        XByteField("lengthCCC", 0x3),
        BitField("spare", 0x0, 6),
        BitField("pcp", 0x0, 1),
        BitField("dtmf", 0x0, 1)
    ]


class CallStateHdr(Packet):
    """Call State Section 10.5.4.6"""
    name = "Call State"
    fields_desc = [
        BitField("eightBitCS", None, 1),
        XBitField("ieiCS", None, 7),
        BitField("codingStd", 0x0, 2),
        BitField("stateValue", 0x0, 6)
    ]


# len 3 to 43
class CalledPartyBcdNumberHdr(Packet):
    """Called party BCD number Section 10.5.4.7"""
    name = "Called Party BCD Number"
    fields_desc = [
        BitField("eightBitCPBN", None, 1),
        XBitField("ieiCPBN", None, 7),
        XByteField("lengthCPBN", None),
        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("nbPlanId", 0x0, 4),
        # optional
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 80)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 43, a, self.fields_desc, 2)
        if self.lengthCPBN is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to 23
class CalledPartySubaddressHdr(Packet):
    """Called party subaddress Section 10.5.4.8"""
    name = "Called Party Subaddress"
    fields_desc = [
        BitField("eightBitCPS", None, 1),
        XBitField("ieiCPS", None, 7),
        XByteField("lengthCPS", None),
        # optional
        BitField("ext", None, 1),
        BitField("subAddr", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo%d" % x, None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 23, a, self.fields_desc)
        if self.lengthCPS is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 3 to 14
class CallingPartyBcdNumberHdr(Packet):
    """Called party subaddress Section 10.5.4.9"""
    name = "Called Party Subaddress"
    fields_desc = [
        BitField("eightBitCPBN", None, 1),
        XBitField("ieiCPBN", None, 7),
        XByteField("lengthCPBN", None),
        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("nbPlanId", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", None, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", None, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", 0x0, 2),
                         lambda pkt: pkt.ext == 0),
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 20)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 14, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthCPBN is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


# len 2 to 23
class CallingPartySubaddressHdr(Packet):
    """Calling party subaddress  Section 10.5.4.10"""
    name = "Calling Party Subaddress"
    fields_desc = [
        BitField("eightBitCPS", None, 1),
        XBitField("ieiCPS", None, 7),
        XByteField("lengthCPS", None),
        # optional
        BitField("ext1", None, 1),
        BitField("typeAddr", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo%d" % x, None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 23, a, self.fields_desc)
        if self.lengthCPS is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 4 to 32
class CauseHdr(Packet):
    """Cause Section 10.5.4.11"""
    name = "Cause"
    fields_desc = [
        BitField("eightBitC", None, 1),
        XBitField("ieiC", None, 7),

        XByteField("lengthC", None),

        BitField("ext", 0x1, 1),
        BitField("codingStd", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("location", 0x0, 4),

        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("recommendation", 0x0, 7),
                         lambda pkt: pkt.ext == 0),
        # optional
        BitField("ext2", None, 1),
        BitField("causeValue", None, 7),
    ] + [ByteField("diagnositc%d" % x, None) for x in range(0, 27)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 32, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthC is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


class ClirSuppressionHdr(Packet):
    """CLIR suppression Section 10.5.4.11a"""
    name = "Clir Suppression"
    fields_desc = [
        BitField("eightBitCS", None, 1),
        XBitField("ieiCS", None, 7),
    ]


class ClirInvocationHdr(Packet):
    """CLIR invocation Section 10.5.4.11b"""
    name = "Clir Invocation"
    fields_desc = [
        BitField("eightBitCI", None, 1),
        XBitField("ieiCI", None, 7),
    ]


class CongestionLevelHdr(Packet):
    """Congestion level Section 10.5.4.12"""
    name = "Congestion Level"
    fields_desc = [
        XBitField("ieiCL", None, 4),
        BitField("notDef", 0x0, 4)
    ]


# Fix 1/2 len problem
class CongestionLevelAndSpareHalfOctets(Packet):
    name = "Congestion Level and Spare Half Octets"
    fields_desc = [
        BitField("ieiCL", 0x0, 4),
        BitField("spareHalfOctets", 0x0, 4)
    ]


# len 3 to 14
class ConnectedNumberHdr(Packet):
    """Connected number Section 10.5.4.13"""
    name = "Connected Number"
    fields_desc = [
        BitField("eightBitCN", None, 1),
        XBitField("ieiCN", None, 7),

        XByteField("lengthCN", None),

        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("typePlanId", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", None, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", None, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", None, 2),
                         lambda pkt: pkt.ext == 0),

    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 20)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 14, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthCN is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


# len 2 to 23
class ConnectedSubaddressHdr(Packet):
    """Connected subaddress Section 10.5.4.14"""
    name = "Connected Subaddress"
    fields_desc = [
        BitField("eightBitCS", None, 1),
        XBitField("ieiCS", None, 7),

        XByteField("lengthCS", None),
        # optional
        BitField("ext", None, 1),
        BitField("typeOfSub", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo%d" % x, None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 23, a, self.fields_desc)
        if self.lengthCS is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to L3 (251) (done)
class FacilityHdr(Packet):
    """Facility Section 10.5.4.15"""
    name = "Facility"
    fields_desc = [
        BitField("eightBitF", None, 1),
        XBitField("ieiF", None, 7),
        XByteField("lengthF", None),
        # optional
    ] + [ByteField("facilityInfo%d" % x, None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 251, a, self.fields_desc)
        if self.lengthF is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to 5
class HighLayerCompatibilityHdr(Packet):
    """High layer compatibility Section 10.5.4.16"""
    name = "High Layer Compatibility"
    fields_desc = [
        BitField("eightBitHLC", None, 1),
        XBitField("ieiHLC", None, 7),

        XByteField("lengthHLC", None),
        # optional
        BitField("ext", None, 1),
        BitField("codingStd", None, 2),
        BitField("interpret", None, 3),
        BitField("presMeth", None, 2),

        BitField("ext1", None, 1),
        BitField("highLayerId", None, 7),

        ConditionalField(BitField("ext2", 0x1, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("exHiLayerId", 0x0, 7),
                         lambda pkt: pkt.ext1 == 0)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 5, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthHLC is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay
#
# 10.5.4.16.1           Static conditions for the high layer
# compatibility IE contents
#


class KeypadFacilityHdr(Packet):
    """Keypad facility Section 10.5.4.17"""
    name = "Keypad Facility"
    fields_desc = [
        BitField("eightBitKF", None, 1),
        XBitField("ieiKF", None, 7),
        BitField("spare", 0x0, 1),
        BitField("keyPadInfo", 0x0, 7)
    ]


# len 2 to 15
class LowLayerCompatibilityHdr(Packet):
    """Low layer compatibility Section 10.5.4.18"""
    name = "Low Layer Compatibility"
    fields_desc = [
        BitField("eightBitLLC", None, 1),
        XBitField("ieiLLC", None, 7),

        XByteField("lengthLLC", None),
        # optional
    ] + [ByteField("rest%d" % x, None) for x in range(0, 13)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 15, a, self.fields_desc)
        if self.lengthLLC is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MoreDataHdr(Packet):
    """More data Section 10.5.4.19"""
    name = "More Data"
    fields_desc = [
        BitField("eightBitMD", None, 1),
        XBitField("ieiMD", None, 7),
    ]


class NotificationIndicatorHdr(Packet):
    """Notification indicator Section 10.5.4.20"""
    name = "Notification Indicator"
    fields_desc = [
        BitField("eightBitNI", None, 1),
        XBitField("ieiNI", None, 7),
        BitField("ext", 0x1, 1),
        BitField("notifDesc", 0x0, 7)
    ]


class ProgressIndicatorHdr(Packet):
    """Progress indicator Section 10.5.4.21"""
    name = "Progress Indicator"
    fields_desc = [
        BitField("eightBitPI", None, 1),
        XBitField("ieiPI", None, 7),
        XByteField("lengthPI", 0x2),
        BitField("ext", 0x1, 1),
        BitField("codingStd", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("location", 0x0, 4),
        BitField("ext1", 0x1, 1),
        BitField("progressDesc", 0x0, 7)
    ]


class RecallTypeHdr(Packet):
    """Recall type $(CCBS)$  Section 10.5.4.21a"""
    name = "Recall Type $(CCBS)$"
    fields_desc = [
        BitField("eightBitRT", None, 1),
        XBitField("ieiRT", None, 7),
        BitField("spare", 0x0, 5),
        BitField("recallType", 0x0, 3)
    ]


# len 3 to 19
class RedirectingPartyBcdNumberHdr(Packet):
    """Redirecting party BCD number  Section 10.5.4.21b"""
    name = "Redirecting Party BCD Number"
    fields_desc = [
        BitField("eightBitRPBN", None, 1),
        XBitField("ieiRPBN", None, 7),

        XByteField("lengthRPBN", None),

        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("numberingPlan", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", None, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", None, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", None, 2),
                         lambda pkt: pkt.ext == 0),
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 30)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 19, a, self.fields_desc)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthRPBN is None:
            p = p[:1] + chb(len(p) - 2) + p[2:]
        return p + pay


# length 2 to 23
class RedirectingPartySubaddressHdr(Packet):
    """Redirecting party subaddress  Section 10.5.4.21c"""
    name = "Redirecting Party BCD Number"
    fields_desc = [
        BitField("eightBitRPS", None, 1),
        XBitField("ieiRPS", None, 7),

        XByteField("lengthRPS", None),
        # optional
        BitField("ext", None, 1),
        BitField("typeSub", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo%d" % x, None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 23, a, self.fields_desc)
        if self.lengthRPS is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class RepeatIndicatorHdr(Packet):
    """Repeat indicator Section 10.5.4.22"""
    name = "Repeat Indicator"
    fields_desc = [
        XBitField("ieiRI", None, 4),
        BitField("repeatIndic", 0x0, 4)
    ]


class ReverseCallSetupDirectionHdr(Packet):
    """Reverse call setup direction Section 10.5.4.22a"""
    name = "Reverse Call Setup Direction"
    fields_desc = [
        ByteField("ieiRCSD", 0x0)
    ]


# no upper length min 2(max for L3) (251)
class SetupContainerHdr(Packet):
    """SETUP Container $(CCBS)$ Section 10.5.4.22b"""
    name = "Setup Container $(CCBS)$"
    fields_desc = [
        BitField("eightBitSC", None, 1),
        XBitField("ieiSC", None, 7),
        XByteField("lengthSC", None),
        # optional
    ] + [ByteField("mess%d" % x, None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 251, a, self.fields_desc)
        if self.lengthSC is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class SignalHdr(Packet):
    """Signal Section 10.5.4.23"""
    name = "Signal"
    fields_desc = [
        BitField("eightBitS", None, 1),
        XBitField("ieiS", None, 7),
        ByteField("sigValue", 0x0)
    ]


# length 2 to max for L3 message (251)
class SsVersionIndicatorHdr(Packet):
    """SS Version Indicator  Section 10.5.4.24"""
    name = "SS Version Indicator"
    fields_desc = [
        BitField("eightBitSVI", None, 1),
        XBitField("ieiSVI", None, 7),
        XByteField("lengthSVI", None),
        # optional
    ] + [ByteField("info%d" % x, None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 251, a, self.fields_desc)
        if self.lengthSVI is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# length 3 to 35 or 131
class UserUserHdr(Packet):
    """User-user Section 10.5.4.25"""
    name = "User-User"
    fields_desc = [
        BitField("eightBitUU", None, 1),
        XBitField("ieiUU", None, 7),

        XByteField("lengthUU", None),  # dynamic length of field depending
        # of the type of message
        # let user decide which length he
        # wants to take
        # => more fuzzing options
        ByteField("userUserPD", 0x0),
        # optional
    ] + [ByteField("userUserInfo%d" % x, None) for x in range(1, 132)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 131, a, self.fields_desc)
        if self.lengthUU is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class AlertingPatternHdr(Packet):
    """Alerting Pattern 10.5.4.26"""
    name = "Alerting Pattern"
    fields_desc = [
        BitField("eightBitAP", None, 1),
        XBitField("ieiAP", None, 7),
        XByteField("lengthAP", 0x3),
        BitField("spare", 0x0, 4),
        BitField("alertingValue", 0x0, 4)
    ]


class AllowedActionsHdr(Packet):
    """Allowed actions $(CCBS)$ Section 10.5.4.26"""
    name = "Allowed Actions $(CCBS)$"
    fields_desc = [
        BitField("eightBitAA", None, 1),
        XBitField("ieiAA", None, 7),
        XByteField("lengthAP", 0x3),
        BitField("CCBS", 0x0, 1),
        BitField("spare", 0x0, 7)
    ]


#
# 10.5.5 GPRS mobility management information elements
#

class AttachResult(Packet):
    """Attach result Section 10.5.5.1"""
    name = "Attach Result"
    fields_desc = [
        XBitField("ieiAR", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("result", 0x1, 3)
    ]


class AttachTypeHdr(Packet):
    """Attach type Section 10.5.5.2"""
    name = "Attach Type"
    fields_desc = [
        XBitField("ieiAT", None, 4),
        BitField("spare", 0x0, 1),
        BitField("type", 0x1, 3)
    ]


# Fix 1/2 len problem
class AttachTypeAndCiphKeySeqNr(Packet):
    name = "Attach Type and Cipher Key Sequence Number"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("type", 0x1, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class CipheringAlgorithm(Packet):
    """Ciphering algorithm Section 10.5.5.3"""
    name = "Ciphering Algorithm"
    fields_desc = [
        XBitField("ieiCA", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("type", 0x1, 3)
    ]


# Fix 1/2 len problem
class CipheringAlgorithmAndImeisvRequest(Packet):
    name = "Ciphering Algorithm and Imeisv Request"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("type", 0x1, 3),
        BitField("spare", 0x0, 1),
        BitField("imeisvVal", 0x0, 3)
    ]


# [Spare]
class TmsiStatus(Packet):
    """[Spare] TMSI status Section 10.5.5.4"""
    name = "[Spare] TMSI Status"
    fields_desc = [
        XBitField("ieiTS", None, 4),
        BitField("spare", 0x0, 3),
        BitField("flag", 0x1, 1)
    ]


class DetachType(Packet):
    """Detach type Section 10.5.5.5"""
    name = "Detach Type"
    fields_desc = [
        XBitField("ieiDT", 0x0, 4),
        BitField("poweroff", 0x0, 1),
        BitField("type", 0x1, 3)
    ]


# Fix 1/2 len problem
class DetachTypeAndForceToStandby(Packet):
    name = "Detach Type and Force To Standby"
    fields_desc = [
        BitField("poweroff", 0x0, 1),
        BitField("type", 0x1, 3),
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3)
    ]


# Fix 1/2 len problem
class DetachTypeAndSpareHalfOctets(Packet):
    name = "Detach Type and Spare Half Octets"
    fields_desc = [
        BitField("poweroff", 0x0, 1),
        BitField("type", 0x1, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class DrxParameter(Packet):
    """DRX parameter Section 10.5.5.6"""
    name = "DRX Parameter"
    fields_desc = [
        ByteField("ieiDP", 0x0),
        ByteField("splitPG", 0x0),
        BitField("spare", 0x0, 4),
        BitField("splitCCCH", 0x0, 1),
        BitField("NonDrxTimer", 0x1, 3)
    ]


class ForceToStandby(Packet):
    """Force to standby Section 10.5.5.7"""
    name = "Force To Standby"
    fields_desc = [
        XBitField("ieiFTS", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3)
    ]


# Fix 1/2 len problem
class ForceToStandbyAndAcReferenceNumber(Packet):
    name = "Force To Standby And Ac Reference Number"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3),
        BitField("acRefVal", 0x0, 4)
    ]


# Fix 1/2 len problem
class ForceToStandbyAndUpdateResult(Packet):
    name = "Force To Standby And Update Result"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("updateResVal", 0x0, 3)
    ]


# Fix 1/2 len problem
class ForceToStandbyAndSpareHalfOctets(Packet):
    name = "Force To Standby And Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class PTmsiSignature(Packet):
    """P-TMSI signature Section 10.5.5.8"""
    name = "P-TMSI Signature"
    fields_desc = [
        ByteField("ieiPTS", 0x0),
        BitField("signature", 0x0, 24)
    ]


class IdentityType2(Packet):
    """Identity type 2 Section 10.5.5.9"""
    name = "Identity Type 2"
    fields_desc = [
        XBitField("ieiIT2", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("typeOfIdentity", 0x0, 3)
    ]


# Fix 1/2 len problem
class IdentityType2AndforceToStandby(Packet):
    name = "Identity Type 2 and Force to Standby"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("typeOfIdentity", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("forceStandby", 0x0, 3)
    ]


class ImeisvRequest(Packet):
    """IMEISV request Section 10.5.5.10"""
    name = "IMEISV Request"
    fields_desc = [
        XBitField("ieiIR", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("imeisvVal", 0x0, 3)
    ]


# Fix 1/2 len problem
class ImeisvRequestAndForceToStandby(Packet):
    name = "IMEISV Request and Force To Standby"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("imeisvVal", 0x0, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


# length 4 to 19
class ReceiveNpduNumbersList(Packet):
    """Receive N-PDU Numbers list Section 10.5.5.11"""
    name = "Receive N-PDU Numbers list"
    fields_desc = [
        ByteField("ieiRNNL", 0x0),

        XByteField("lengthRNNL", None),

        BitField("nbList0", 0x0, 16),
        # optional
    ] + [ByteField("nbList%d" % x, None) for x in range(1, 16)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 19, a, self.fields_desc)
        if self.lengthRNNL is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MsNetworkCapability(Packet):
    """MS network capability Section 10.5.5.12"""
    name = "MS Network Capability"
    fields_desc = [
        ByteField("ieiMNC", 0x0),
        XByteField("lengthMNC", 0x3),
        ByteField("msNetValue", 0x0)
    ]


# length 6 to 14
class MsRadioAccessCapability(Packet):
    """MS Radio Access capability Section 10.5.5.12a"""
    name = "MS Radio Access Capability"
    fields_desc = [
        ByteField("ieiMRAC", 0x24),

        XByteField("lengthMRAC", None),

        BitField("spare1", 0x0, 1),  # ...

        BitField("accessCap", 0x0, 4),
        BitField("accessTechType", 0x0, 4),
        # access capability
        BitField("bool", 0x0, 1),
        BitField("lengthContent", 0x0, 7),
        BitField("spare1", 0x0, 1),  # ...
        # content
        BitField("pwrCap", 0x0, 3),
        BitField("bool1", 0x0, 1),
        BitField("a51", 0x0, 1),
        BitField("a52", 0x0, 1),
        BitField("a53", 0x0, 1),
        BitField("a54", 0x0, 1),

        BitField("a55", 0x0, 1),
        BitField("a56", 0x0, 1),
        BitField("a57", 0x0, 1),
        BitField("esInd", 0x0, 1),
        BitField("ps", 0x0, 1),
        BitField("vgcs", 0x0, 1),
        BitField("vbs", 0x0, 1),
        BitField("bool2", 0x0, 1),
        # multislot
        BitField("bool3", 0x0, 1),
        BitField("hscsd", 0x0, 5),

        BitField("bool4", 0x0, 1),
        BitField("gprs", 0x0, 5),
        BitField("gprsExt", 0x0, 1),
        BitField("bool5", 0x0, 1),

        BitField("smsVal", 0x0, 4),
        BitField("smVal", 0x0, 4)
    ]


# 10.5.5.13 Spare
# This is intentionally left spare.

class GmmCause(Packet):
    """GMM cause Section 10.5.5.14"""
    name = "GMM Cause"
    fields_desc = [
        ByteField("ieiGC", 0x0),
        ByteField("causeValue", 0x0)
    ]


class RoutingAreaIdentification(Packet):
    """Routing area identification Section 10.5.5.15"""
    name = "Routing Area Identification"
    fields_desc = [
        ByteField("ieiRAI", 0x0),
        BitField("mccDigit2", 0x0, 4),
        BitField("mccDigit1", 0x0, 4),
        BitField("mncDigit3", 0x0, 4),
        BitField("mccDigit3", 0x0, 4),
        BitField("mccDigit2", 0x0, 4),
        BitField("mccDigit1", 0x0, 4),
        ByteField("LAC", 0x0),
        ByteField("LAC1", 0x0),
        ByteField("LAC", 0x0)
    ]
# 10.5.5.16 Spare
# This is intentionally left spare.


class UpdateResult(Packet):
    """Update result Section 10.5.5.17"""
    name = "Update Result"
    fields_desc = [
        XBitField("ieiUR", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("updateResVal", 0x0, 3)
    ]


class UpdateType(Packet):
    """Update type Section 10.5.5.18"""
    name = "Update Type"
    fields_desc = [
        XBitField("ieiUT", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("updateTypeVal", 0x0, 3)
    ]


# Fix 1/2 len problem
class UpdateTypeAndCiphKeySeqNr(Packet):
    name = "Update Type and Cipher Key Sequence Number"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("updateTypeVal", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3)
    ]


class AcReferenceNumber(Packet):
    """A&C reference number Section 10.5.5.19"""
    name = "A&C Reference Number"
    fields_desc = [
        XBitField("ieiARN", 0x0, 4),
        BitField("acRefVal", 0x0, 4)
    ]


# Fix 1/2 len problem
class AcReferenceNumberAndSpareHalfOctets(Packet):
    name = "A&C Reference Number and Spare Half Octets"
    fields_desc = [
        BitField("acRefVal", 0x0, 4),
        BitField("spareHalfOctets", 0x0, 4)
    ]
#
# 10.5.6 Session management information elements
#
# length 3 to 102


class AccessPointName(Packet):
    """Access Point Name Section 10.5.6.1"""
    name = "Access Point Name"
    fields_desc = [
        ByteField("ieiAPN", 0x0),
        XByteField("lengthAPN", None),
        ByteField("apName", 0x0),
        # optional
    ] + [ByteField("apName%d" % x, None) for x in range(1, 100)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 102, a, self.fields_desc)
        if self.lengthAPN is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class NetworkServiceAccessPointIdentifier(Packet):
    """Network service access point identifier Section 10.5.6.2"""
    name = "Network Service Access Point Identifier"
    fields_desc = [
        ByteField("ieiNSAPI", 0x0),
        BitField("spare", 0x0, 4),
        BitField("nsapiVal", 0x0, 4)
    ]


# length 2 to 253
class ProtocolConfigurationOptions(Packet):
    """Protocol configuration options Section 10.5.6.3"""
    name = "Protocol Configuration Options"
    fields_desc = [
        ByteField("ieiPCO", 0x0),

        XByteField("lengthPCO", None),
        # optional
        BitField("ext", None, 1),
        BitField("spare", None, 4),
        BitField("configProto", None, 3),
    ] + list(itertools.chain(*[[
        ByteField("protoId%d" % x, None),
        ByteField("lenProto%d" % x, None),
        ByteField("proto%dContent" % x, None),
    ] for x in range(1, 84)]))

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 253, a, self.fields_desc)
        if self.lengthPCO is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 4 to 20
class PacketDataProtocolAddress(Packet):
    """Packet data protocol address Section 10.5.6.4"""
    name = "Packet Data Protocol Address"
    fields_desc = [
        ByteField("ieiPDPA", 0x0),

        XByteField("lengthPDPA", None),

        BitField("spare", 0x0, 4),
        BitField("pdpTypeOrga", 0x0, 4),

        ByteField("pdpTypeNb", 0x0),
        # optional
    ] + [ByteField("addressInfo%d" % x, None) for x in range(1, 17)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 20, a, self.fields_desc)
        if self.lengthPDPA is None:
            p = p[:1] + chb(res[1]) + p[2:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class QualityOfService(Packet):
    """Quality of service Section 10.5.6.5"""
    name = "Quality of Service"
    fields_desc = [
        ByteField("ieiQOS", 0x0),
        XByteField("lengthQOS", 0x5),

        BitField("spare", 0x0, 2),
        BitField("delayClass", 0x0, 3),
        BitField("reliaClass", 0x0, 3),

        BitField("peak", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("precedenceCl", 0x0, 3),

        BitField("spare", 0x0, 3),
        BitField("mean", 0x0, 5)
    ]


class SmCause(Packet):
    """SM cause Section 10.5.6.6"""
    name = "SM Cause"
    fields_desc = [
        ByteField("ieiSC", 0x0),
        ByteField("causeVal", 0x0)
    ]

# 10.5.6.7 Spare
# This is intentionally left spare.


class AaDeactivationCause(Packet):
    """AA deactivation cause Section 10.5.6.8"""
    name = "AA Deactivation Cause"
    fields_desc = [
        XBitField("ieiADC", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("aaVal", 0x0, 3)
    ]


# Fix 1/2 len problem
class AaDeactivationCauseAndSpareHalfOctets(Packet):
    name = "AA Deactivation Cause and Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("aaVal", 0x0, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class LlcServiceAccessPointIdentifier(Packet):
    """LLC service access point identifier Section 10.5.6.9"""
    name = "LLC Service Access Point Identifier"
    fields_desc = [
        ByteField("ieiLSAPI", None),
        BitField("spare", 0x0, 4),
        BitField("llcVal", 0x0, 4)
    ]


#
# 10.5.7 GPRS Common information elements
#

# 10.5.7.1 [Spare]

class RadioPriority(Packet):
    """Radio priority Section 10.5.7.2"""
    name = "Radio Priority"
    fields_desc = [
        XBitField("ieiRP", 0x0, 4),
        BitField("spare", 0x1, 1),
        BitField("rplv", 0x0, 3)
    ]


# Fix 1/2 len problem
class RadioPriorityAndSpareHalfOctets(Packet):
    name = "Radio Priority and Spare Half Octets"
    fields_desc = [
        BitField("spare", 0x1, 1),
        BitField("rplv", 0x0, 3),
        BitField("spareHalfOctets", 0x0, 4)
    ]


class GprsTimer(Packet):
    """GPRS Timer Section 10.5.7.3"""
    name = "GPRS Timer"
    fields_desc = [
        ByteField("ieiGT", 0x0),
        BitField("unit", 0x0, 3),
        BitField("timerVal", 0x0, 5)
    ]


class CellIdentity(Packet):
    """ Cell identity Section 10.5.1.1 """
    name = "Cell Identity"
    fields_desc = [
        ByteField("ciValue1", 0x0),
        ByteField("ciValue2", 0x0)
    ]


class CiphKeySeqNr(Packet):
    """ Ciphering Key Sequence Number Section 10.5.1.2 """
    name = "Cipher Key Sequence Number"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("keySeq", 0x0, 3)
    ]


class LocalAreaId(Packet):
    """ Local Area Identification Section 10.5.1.3 """
    name = "Location Area Identification"
    fields_desc = [
        BitField("mccDigit2", 0x0, 4),
        BitField("mccDigit1", 0x0, 4),
        BitField("mncDigit3", 0x0, 4),
        BitField("mccDigit3", 0x0, 4),
        BitField("mncDigit2", 0x0, 4),
        BitField("mncDigit1", 0x0, 4),
        ByteField("lac1", 0x0),
        ByteField("lac2", 0x0)
    ]
#
# The Mobile Identity is a type 4 information element with a minimum
# length of 3 octet and 11 octets length maximal.
#


# len 3 - 11
class MobileId(Packet):
    """ Mobile Identity  Section 10.5.1.4 """
    name = "Mobile Identity"
    fields_desc = [
        XByteField("lengthMI", None),
        BitField("idDigit1", 0x0, 4),
        BitField("oddEven", 0x0, 1),
        BitField("typeOfId", 0x0, 3),
        # optional
    ] + list(itertools.chain(*[[
        BitField("idDigit%d_1" % x, None, 4),
        BitField("idDigit%d" % x, None, 4),
    ] for x in range(2, 10)]))

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 10, a, self.fields_desc, 1)
        if self.lengthMI is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MobileStationClassmark1(Packet):
    """ Mobile Station Classmark 1 Section 10.5.1.5 """
    name = "Mobile Station Classmark 1"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("revisionLvl", 0x0, 2),
        BitField("esInd", 0x0, 1),
        BitField("a51", 0x0, 1),
        BitField("rfPowerCap", 0x0, 3)
    ]


class MobileStationClassmark2(Packet):
    """ Mobile Station Classmark 2 Section 10.5.1.6 """
    name = "Mobile Station Classmark 2"
    fields_desc = [
        XByteField("lengthMSC2", 0x3),
        BitField("spare", 0x0, 1),
        BitField("revisionLvl", 0x0, 2),
        BitField("esInd", 0x0, 1),
        BitField("a51", 0x0, 1),
        BitField("rfPowerCap", 0x0, 3),
        BitField("spare1", 0x0, 1),
        BitField("psCap", 0x0, 1),
        BitField("ssScreenInd", 0x0, 2),
        BitField("smCaPabi", 0x0, 1),
        BitField("vbs", 0x0, 1),
        BitField("vgcs", 0x0, 1),
        BitField("fc", 0x0, 1),
        BitField("cm3", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("lcsvaCap", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("soLsa", 0x0, 1),
        BitField("cmsp", 0x0, 1),
        BitField("a53", 0x0, 1),
        BitField("a52", 0x0, 1)
    ]


class DescriptiveGroupOrBroadcastCallReference(Packet):
    """ Descriptive group or broadcast call reference  Section 10.5.1.9 """
    name = "Descriptive Group or Broadcast Call Reference"
    fields_desc = [
        BitField("binCallRef", 0x0, 27),
        BitField("sf", 0x0, 1),
        BitField("fa", 0x0, 1),
        BitField("callPrio", 0x0, 3),
        BitField("cipherInfo", 0x0, 4),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("spare4", 0x0, 1)
    ]


class PdAndSapi(Packet):
    """ PD and SAPI $(CCBS)$  Section 10.5.1.10a """
    name = "PD and SAPI $(CCBS)$"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("sapi", 0x0, 2),
        BitField("pd", 0x0, 4)
    ]


class PriorityLevel(Packet):
    """ Priority Level Section 10.5.1.11 """
    name = "Priority Level"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("callPrio", 0x0, 3)
    ]

#
# Radio Resource management information elements
#


# len 6 to max for L3 message (251)
class BaRange(Packet):
    """ BA Range Section 10.5.2.1a """
    name = "BA Range"
    fields_desc = [

        XByteField("lengthBR", None),
        # error: byte format requires -128 <= number <= 127
        ByteField("nrOfRanges", 0x0),
        #              # rX = range X
        #              # L o = Lower H i = higher
        #              # H p = high Part Lp = low Part
        ByteField("r1LoHp", 0x0),
        BitField("r1LoLp", 0x0, 3),
        BitField("r1HiHp", 0x0, 5),
        BitField("r1HiLp", 0x0, 4),

        BitField("r2LoHp", 0x0, 4),
        # optional
        BitField("r2LoLp", None, 5),
        BitField("r2HiHp", None, 3),
        ByteField("r2HiLp", None),
    ] + list(itertools.chain(*[[
        ByteField("r%dLoHp" % x, None),
        BitField("r%dLoLp" % x, None, 5),
        BitField("r%dHiHp" % x, None, 3),
        ByteField("r%dHiLp" % x, None),
    ] for x in range(3, 85)]))

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(5, 253, a, self.fields_desc, 1)
        if self.lengthBR is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 3 to max for L3 message (251)
class BaListPref(Packet):
    """ BA List Pref Section 10.5.2.1c """
    name = "BA List Pref"
    fields_desc = [
        XByteField("lengthBLP", None),

        BitField("fixBit", 0x0, 1),
        BitField("rangeLower", 0x0, 10),
        BitField("fixBit2", 0x0, 1),
        BitField("rangeUpper", 0x0, 10),
        BitField("baFreq", 0x0, 10),
        BitField("sparePad", 0x0, 8)
    ]


# len 17 || Have a look at the specs for the field format
# Bit map 0 format
# Range 1024 format
# Range  512 format
# Range  256 format
# Range  128 format
# Variable bit map format
class CellChannelDescription(Packet):
    """ Cell Channel Description  Section 10.5.2.1b """
    name = "Cell Channel Description "
    fields_desc = [
        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        ByteField("bit120", 0x0),
        ByteField("bit112", 0x0),
        ByteField("bit104", 0x0),
        ByteField("bit96", 0x0),
        ByteField("bit88", 0x0),
        ByteField("bit80", 0x0),
        ByteField("bit72", 0x0),
        ByteField("bit64", 0x0),
        ByteField("bit56", 0x0),
        ByteField("bit48", 0x0),
        ByteField("bit40", 0x0),
        ByteField("bit32", 0x0),
        ByteField("bit24", 0x0),
        ByteField("bit16", 0x0),
        ByteField("bit8", 0x0)
    ]


class CellDescription(Packet):
    """ Cell Description  Section 10.5.2.2 """
    name = "Cell Description"
    fields_desc = [
        BitField("bcchHigh", 0x0, 2),
        BitField("ncc", 0x0, 3),
        BitField("bcc", 0x0, 3),
        ByteField("bcchLow", 0x0)
    ]


class CellOptionsBCCH(Packet):
    """ Cell Options (BCCH)  Section 10.5.2.3 """
    name = "Cell Options (BCCH)"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("pwrc", 0x0, 1),
        BitField("dtx", 0x0, 2),
        BitField("rLinkTout", 0x0, 4)
    ]


class CellOptionsSACCH(Packet):
    """ Cell Options (SACCH) Section 10.5.2.3a """
    name = "Cell Options (SACCH)"
    fields_desc = [
        BitField("dtx", 0x0, 1),
        BitField("pwrc", 0x0, 1),
        BitField("dtx", 0x0, 1),
        BitField("rLinkTout", 0x0, 4)
    ]


class CellSelectionParameters(Packet):
    """ Cell Selection Parameters Section 10.5.2.4 """
    name = "Cell Selection Parameters"
    fields_desc = [
        BitField("cellReselect", 0x0, 3),
        BitField("msTxPwrMax", 0x0, 5),
        BitField("acs", None, 1),
        BitField("neci", None, 1),
        BitField("rxlenAccMin", None, 6)
    ]


class MacModeAndChannelCodingRequest(Packet):
    """ MAC Mode and Channel Coding Requested Section 10.5.2.4a """
    name = "MAC Mode and Channel Coding Requested"
    fields_desc = [
        BitField("macMode", 0x0, 2),
        BitField("cs", 0x0, 2)
    ]


class ChannelDescription(Packet):
    """ Channel Description  Section 10.5.2.5 """
    name = "Channel Description"
    fields_desc = [

        BitField("channelTyp", 0x0, 5),
        BitField("tn", 0x0, 3),

        BitField("tsc", 0x0, 3),
        BitField("h", 0x1, 1),
        BitField("maioHi", 0x0, 4),

        BitField("maioLo", 0x0, 2),
        BitField("hsn", 0x0, 6)
    ]


class ChannelDescription2(Packet):
    """ Channel Description 2 Section 10.5.2.5a """
    name = "Channel Description 2"
    fields_desc = [
        BitField("channelTyp", 0x0, 5),
        BitField("tn", 0x0, 3),
        BitField("tsc", 0x0, 3),
        BitField("h", 0x0, 1),
        # if h=1
        # BitField("maioHi", 0x0, 4),
        # BitField("maioLo", 0x0, 2),
        # BitField("hsn", 0x0, 6)
        BitField("spare", 0x0, 2),
        BitField("arfcnHigh", 0x0, 2),
        ByteField("arfcnLow", 0x0)
    ]


class ChannelMode(Packet):
    """ Channel Mode Section 10.5.2.6 """
    name = "Channel Mode"
    fields_desc = [
        ByteField("mode", 0x0)
    ]


class ChannelMode2(Packet):
    """ Channel Mode 2 Section 10.5.2.7 """
    name = "Channel Mode 2"
    fields_desc = [
        ByteField("mode", 0x0)
    ]


class ChannelNeeded(Packet):
    """ Channel Needed Section 10.5.2.8 """
    name = "Channel Needed"
    fields_desc = [
        BitField("channel2", 0x0, 2),
        BitField("channel1", 0x0, 2),
    ]


class ChannelRequestDescription(Packet):
    """Channel Request Description  Section 10.5.2.8a """
    name = "Channel Request Description"
    fields_desc = [
        BitField("mt", 0x0, 1),
        ConditionalField(BitField("spare", 0x0, 39),
                         lambda pkt: pkt.mt == 0),
        ConditionalField(BitField("spare", 0x0, 3),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("priority", 0x0, 2),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("rlcMode", 0x0, 1),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(BitField("llcFrame", 0x1, 1),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("reqBandMsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("reqBandLsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("rlcMsb", 0x0),
                         lambda pkt: pkt.mt == 1),
        ConditionalField(ByteField("rlcLsb", 0x0),
                         lambda pkt: pkt.mt == 1)
    ]


class CipherModeSetting(Packet):
    """Cipher Mode Setting Section 10.5.2.9 """
    name = "Cipher Mode Setting"
    fields_desc = [
        BitField("algoId", 0x0, 3),
        BitField("sc", 0x0, 1),
    ]


class CipherResponse(Packet):
    """Cipher Response Section 10.5.2.10 """
    name = "Cipher Response"
    fields_desc = [
        BitField("spare", 0x0, 3),
        BitField("cr", 0x0, 1),
    ]


class ControlChannelDescription(Packet):
    """Control Channel Description Section 10.5.2.11 """
    name = "Control Channel Description"
    fields_desc = [

        BitField("spare", 0x0, 1),
        BitField("att", 0x0, 1),
        BitField("bsAgBlksRes", 0x0, 3),
        BitField("ccchConf", 0x0, 3),

        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("spare3", 0x0, 1),
        BitField("spare4", 0x0, 1),
        BitField("bsPaMfrms", 0x0, 3),

        ByteField("t3212", 0x0)
    ]


class FrequencyChannelSequence(Packet):
    """Frequency Channel Sequence Section 10.5.2.12"""
    name = "Frequency Channel Sequence"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("lowestArfcn", 0x0, 7),
    ] + [
        BitField("skipArfcn" + "%02d" % x, 0x0, 4) for x in range(1, 17)
    ]


class FrequencyList(Packet):
    """Frequency List Section 10.5.2.13"""
    name = "Frequency List"
 # Problem:
 # There are several formats for the Frequency List information
 # element, distinguished by the "format indicator" subfield.
 # Some formats are frequency bit maps, the others use a special encoding
 # scheme.
    fields_desc = [
        XByteField("lengthFL", None),

        BitField("formatID", 0x0, 2),
        BitField("spare", 0x0, 2),
        BitField("arfcn124", 0x0, 1),
        BitField("arfcn123", 0x0, 1),
        BitField("arfcn122", 0x0, 1),
        BitField("arfcn121", 0x0, 1),

        ByteField("arfcn120", 0x0),
        ByteField("arfcn112", 0x0),
        ByteField("arfcn104", 0x0),
        ByteField("arfcn96", 0x0),
        ByteField("arfcn88", 0x0),
        ByteField("arfcn80", 0x0),
        ByteField("arfcn72", 0x0),
        ByteField("arfcn64", 0x0),
        ByteField("arfcn56", 0x0),
        ByteField("arfcn48", 0x0),
        ByteField("arfcn40", 0x0),
        ByteField("arfcn32", 0x0),
        ByteField("arfcn24", 0x0),
        ByteField("arfcn16", 0x0),
        ByteField("arfcn8", 0x0)
    ]


# len 4 to 13
class GroupChannelDescription(Packet):
    """Group Channel Description Section 10.5.2.14b"""
    name = "Group Channel Description"
    fields_desc = [
        XByteField("lengthGCD", None),

        BitField("channelType", 0x0, 5),
        BitField("tn", 0x0, 3),

        BitField("tsc", 0x0, 3),
        BitField("h", 0x0, 1),
        # if  h == 0 the  packet looks the following way:
        ConditionalField(BitField("spare", 0x0, 2),
                         lambda pkt: pkt. h == 0x0),
        ConditionalField(BitField("arfcnHi", 0x0, 2),
                         lambda pkt: pkt. h == 0x0),
        ConditionalField(ByteField("arfcnLo", None),
                         lambda pkt: pkt. h == 0x0),
        # if  h == 1 the  packet looks the following way:
        ConditionalField(BitField("maioHi", 0x0, 4),
                         lambda pkt: pkt. h == 0x1),
        ConditionalField(BitField("maioLo", None, 2),
                         lambda pkt: pkt. h == 0x1),
        ConditionalField(BitField("hsn", None, 6),
                         lambda pkt: pkt. h == 0x1),
        # finished with conditional fields
        ByteField("maC6", None),
        ByteField("maC7", None),
        ByteField("maC8", None),
        ByteField("maC9", None),
        ByteField("maC10", None),
        ByteField("maC11", None),
        ByteField("maC12", None),
        ByteField("maC13", None),
        ByteField("maC14", None)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(4, 13, a, self.fields_desc, 1)
        if self.lengthGCD is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class GprsResumption(Packet):
    """GPRS Resumption  Section 10.5.2.14c"""
    name = "GPRS Resumption"
    fields_desc = [
        BitField("spare", 0x0, 3),
        BitField("ack", 0x0, 1)
    ]


class HandoverReference(Packet):
    """Handover Reference Section 10.5.2.15"""
    name = "Handover Reference"
    fields_desc = [
        ByteField("handoverRef", 0x0)
    ]


class IraRestOctets(Packet):
    """IAR Rest Octets Section 10.5.2.17"""
    name = "IAR Rest Octets"
    fields_desc = [
        BitField("spare" + str(x), 0x1, 1) for x in range(1, 25)
    ]


# len is 1 to 5 what do we do with the variable size? no length
# field?! WTF
class IaxRestOctets(Packet):
    """IAX Rest Octets Section 10.5.2.18"""
    name = "IAX Rest Octets"
    fields_desc = [
        BitField("spare01", 0x0, 1),
        BitField("spare02", 0x0, 1),
        BitField("spare03", 0x1, 1),
        BitField("spare04", 0x0, 1),
        BitField("spare05", 0x1, 1),
        BitField("spare06", 0x0, 1),
        BitField("spare07", 0x1, 1),
        BitField("spare08", 0x1, 1),
        ByteField("spareB1", None),
        ByteField("spareB2", None),
        ByteField("spareB3", None)
    ]


class L2PseudoLength(Packet):
    """L2 Pseudo Length Section 10.5.2.19"""
    name = "L2 Pseudo Length"
    fields_desc = [
        BitField("l2pLength", None, 6),
        BitField("bit2", 0x0, 1),
        BitField("bit1", 0x1, 1)
    ]


class MeasurementResults(Packet):
    """Measurement Results Section 10.5.2.20"""
    name = "Measurement Results"
    fields_desc = [
        BitField("baUsed", 0x0, 1),
        BitField("dtxUsed", 0x0, 1),
        BitField("rxLevFull", 0x0, 6),

        BitField("spare", 0x0, 1),
        BitField("measValid", 0x0, 1),
        BitField("rxLevSub", 0x0, 6),

        BitField("spare0", 0x0, 1),
        BitField("rxqualFull", 0x0, 3),
        BitField("rxqualSub", 0x0, 3),
        BitField("noNcellHi", 0x0, 1),

        BitField("noNcellLo", 0x0, 2),
        BitField("rxlevC1", 0x0, 6),

        BitField("bcchC1", 0x0, 5),
        BitField("bsicC1Hi", 0x0, 3),

        BitField("bsicC1Lo", 0x0, 3),
        BitField("rxlevC2", 0x0, 5),

        BitField("rxlevC2Lo", 0x0, 1),
        BitField("bcchC2", 0x0, 5),
        BitField("bsicC2Hi", 0x0, 2),

        BitField("bscicC2Lo", 0x0, 4),
        BitField("bscicC2Hi", 0x0, 4),

        BitField("rxlevC3Lo", 0x0, 2),
        BitField("bcchC3", 0x0, 5),
        BitField("rxlevC3Hi", 0x0, 1),

        BitField("bsicC3Lo", 0x0, 5),
        BitField("bsicC3Hi", 0x0, 3),

        BitField("rxlevC4Lo", 0x0, 3),
        BitField("bcchC4", 0x0, 5),

        BitField("bsicC4", 0x0, 6),
        BitField("rxlevC5Hi", 0x0, 2),

        BitField("rxlevC5Lo", 0x0, 4),
        BitField("bcchC5Hi", 0x0, 4),

        BitField("bcchC5Lo", 0x0, 1),
        BitField("bsicC5", 0x0, 6),
        BitField("rxlevC6", 0x0, 1),

        BitField("rxlevC6Lo", 0x0, 5),
        BitField("bcchC6Hi", 0x0, 3),

        BitField("bcchC6Lo", 0x0, 3),
        BitField("bsicC6", 0x0, 5)
    ]


class GprsMeasurementResults(Packet):
    """GPRS Measurement Results Section 10.5.2.20a"""
    name = "GPRS Measurement Results"
    fields_desc = [
        BitField("cValue", 0x0, 6),
        BitField("rxqualHi", 0x0, 2),
        BitField("rxqL", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("signVar", 0x0, 6)
    ]


# len 3 to 10
class MobileAllocation(Packet):
    """Mobile Allocation Section 10.5.2.21"""
    name = "Mobile Allocation"
    fields_desc = [
        XByteField("lengthMA", None),
        ByteField("maC64", 0x12),
        ByteField("maC56", None),  # optional fields start here
        ByteField("maC48", None),
        ByteField("maC40", None),
        ByteField("maC32", None),
        ByteField("maC24", None),
        ByteField("maC16", None),
        ByteField("maC8", None)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 9, a, self.fields_desc, 1)
        if self.lengthMA is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MobileTimeDifference(Packet):
    """Mobile Time Difference Section 10.5.2.21a"""
    name = "Mobile Time Difference"
    fields_desc = [
        XByteField("lengthMTD", 0x5),
        ByteField("valueHi", 0x0),
        ByteField("valueCnt", 0x0),
        BitField("valueLow", 0x0, 5),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1)
    ]


# min 4 octets max 8
class MultiRateConfiguration(Packet):
    """ MultiRate configuration Section 10.5.2.21aa"""
    name = "MultiRate Configuration"
 # This  packet has a variable length and hence structure. This packet
 # implements the longest possible  packet. If you build a shorter
 #  packet, for example having only 6 bytes, the last 4 bytes are  named
 # "Spare" in the specs. Here they are  named "threshold2"
    fields_desc = [
        XByteField("lengthMRC", None),

        BitField("mrVersion", 0x0, 3),
        BitField("spare", 0x0, 1),
        BitField("icmi", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("startMode", 0x0, 2),

        ByteField("amrCodec", None),

        BitField("spare", None, 2),
        BitField("threshold1", None, 6),

        BitField("hysteresis1", None, 4),
        BitField("threshold2", None, 4),

        BitField("threshold2cnt", None, 2),
        BitField("hysteresis2", None, 4),
        BitField("threshold3", None, 2),

        BitField("threshold3cnt", None, 4),
        BitField("hysteresis3", None, 4)
    ]

    def post_build(self, p, pay):
        # we set the length
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 7, a, self.fields_desc, 1)
        if self.lengthMRC is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to 11
class MultislotAllocation(Packet):
    """Multislot Allocation Section 10.5.2.21b"""
    name = "Multislot Allocation"
    fields_desc = [
        XByteField("lengthMSA", None),
        BitField("ext0", 0x1, 1),
        BitField("da", 0x0, 7),
        ConditionalField(BitField("ext1", 0x1, 1),  # optional
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("ua", 0x0, 7),
                         lambda pkt: pkt.ext0 == 0),
    ] + [ByteField("chan" + str(x), None) for x in range(1, 9)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 11, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthMSA is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


class NcMode(Packet):
    """NC mode Section 10.5.2.21c"""
    name = "NC Mode"
    fields_desc = [
        BitField("spare", 0x0, 2),
        BitField("ncMode", 0x0, 2)
    ]


class NeighbourCellsDescription(Packet):
    """Neighbour Cells Description Section 10.5.2.22"""
    name = "Neighbour Cells Description"
    fields_desc = [
        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("extInd", 0x0, 1),
        BitField("baInd", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        BitField("120bits", 0x0, 120)
    ]


class NeighbourCellsDescription2(Packet):
    """Neighbour Cells Description 2 Section 10.5.2.22a"""
    name = "Neighbour Cells Description 2"
    fields_desc = [
        BitField("bit128", 0x0, 1),
        BitField("multiband", 0x0, 2),
        BitField("baInd", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),
        BitField("120bits", 0x0, 120)
    ]


# len 4
# strange  packet, lots of valid formats

# ideas for the dynamic  packets:
# 1] for user interaction: Create an interactive "builder" based on a
# Q/A process (not very scapy like)
# 2] for usage in scripts, create an alternative  packet for every
# possible  packet layout
#

class DedicatedModeOrTBF(Packet):
    """Dedicated mode or TBF Section 10.5.2.25b"""
    name = "Dedicated Mode or TBF"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("tma", 0x0, 1),
        BitField("downlink", 0x0, 1),
        BitField("td", 0x0, 1)
    ]


class PageMode(Packet):
    """Page Mode Section 10.5.2.26"""
    name = "Page Mode"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("pm", 0x0, 2)
    ]


class NccPermitted(Packet):
    """NCC Permitted Section 10.5.2.27"""
    name = "NCC Permitted"
    fields_desc = [
        ByteField("nccPerm", 0x0)
    ]


class PowerCommand(Packet):
    """Power Command Section 10.5.2.28"""
    name = "Power Command"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("spare2", 0x0, 1),
        BitField("powerLvl", 0x0, 5)
    ]


class PowerCommandAndAccessType(Packet):
    """Power Command and access type  Section 10.5.2.28a"""
    name = "Power Command and Access Type"
    fields_desc = [
        BitField("atc", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("powerLvl", 0x0, 5)
    ]


class RachControlParameters(Packet):
    """RACH Control Parameters Section 10.5.2.29"""
    name = "RACH Control Parameters"
    fields_desc = [
        BitField("maxRetrans", 0x0, 2),
        BitField("txInteger", 0x0, 4),
        BitField("cellBarrAccess", 0x0, 1),
        BitField("re", 0x0, 1),
    ] + [BitField("ACC" + "%02d" % x, 0x0, 1) for x in range(15, -1, -1)]


class RequestReference(Packet):
    """Request Reference  Section 10.5.2.30"""
    name = "Request Reference"
    fields_desc = [
        ByteField("ra", 0x0),
        BitField("t1", 0x0, 5),
        BitField("t3Hi", 0x0, 3),
        BitField("t3Lo", 0x0, 3),
        BitField("t2", 0x0, 5)
    ]


class RrCause(Packet):
    """RR Cause  Section 10.5.2.31"""
    name = "RR Cause"
    fields_desc = [
        ByteField("rrCause", 0x0)
    ]


class StartingTime(Packet):
    """Starting Time Section 10.5.2.38"""
    name = "Starting Time"
    fields_desc = [
        ByteField("ra", 0x0),
        BitField("t1", 0x0, 5),
        BitField("t3Hi", 0x0, 3),
        BitField("t3Lo", 0x0, 3),
        BitField("t2", 0x0, 5)
    ]


class SynchronizationIndication(Packet):
    """Synchronization Indication Section 10.5.2.39"""
    name = "Synchronization Indication"
    fields_desc = [
        BitField("nci", 0x0, 1),
        BitField("rot", 0x0, 1),
        BitField("si", 0x0, 2)
    ]


class TimingAdvance(Packet):
    """Timing Advance Section 10.5.2.40"""
    name = "Timing Advance"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1),
        BitField("timingVal", 0x0, 6)
    ]


class TimeDifference(Packet):
    """ Time Difference Section 10.5.2.41"""
    name = "Time Difference"
    fields_desc = [
        XByteField("lengthTD", 0x3),
        ByteField("timeValue", 0x0)
    ]


class Tlli(Packet):
    """ TLLI Section Section 10.5.2.41a"""
    name = "TLLI"
    fields_desc = [
        ByteField("value", 0x0),
        ByteField("value1", 0x0),
        ByteField("value2", 0x0),
        ByteField("value3", 0x0)
    ]


class TmsiPTmsi(Packet):
    """ TMSI/P-TMSI Section 10.5.2.42"""
    name = "TMSI/P-TMSI"
    fields_desc = [
        ByteField("value", 0x0),
        ByteField("value1", 0x0),
        ByteField("value2", 0x0),
        ByteField("value3", 0x0)
    ]


class VgcsTargetModeIdentication(Packet):
    """ VGCS target Mode Indication 10.5.2.42a"""
    name = "VGCS Target Mode Indication"
    fields_desc = [
        XByteField("lengthVTMI", 0x2),
        BitField("targerMode", 0x0, 2),
        BitField("cipherKeyNb", 0x0, 4),
        BitField("spare", 0x0, 1),
        BitField("spare1", 0x0, 1)
    ]


class WaitIndication(Packet):
    """ Wait Indication Section 10.5.2.43"""
    name = "Wait Indication"
    fields_desc = [  # asciiart of specs strange
        ByteField("timeoutVal", 0x0)
    ]


# class Si10RestOctets(Packet):
#     """SI10 rest octets 10.5.2.44"""
#     name = "SI10 rest octets"
#     fields_desc = [


# len 17
class ExtendedMeasurementResults(Packet):
    """EXTENDED MEASUREMENT RESULTS Section 10.5.2.45"""
    name = "Extended Measurement Results"
    fields_desc = [

        BitField("scUsed", None, 1),
        BitField("dtxUsed", None, 1),
        BitField("rxLevC0", None, 6),

        BitField("rxLevC1", None, 6),
        BitField("rxLevC2Hi", None, 2),

        BitField("rxLevC2Lo", None, 4),
        BitField("rxLevC3Hi", None, 4),

        BitField("rxLevC3Lo", None, 3),
        BitField("rxLevC4", None, 5),

        BitField("rxLevC5", None, 6),
        BitField("rxLevC6Hi", None, 2),

        BitField("rxLevC6Lo", None, 4),
        BitField("rxLevC7Hi", None, 4),

        BitField("rxLevC7Lo", None, 2),
        BitField("rxLevC8", None, 6),

        BitField("rxLevC9", None, 6),
        BitField("rxLevC10Hi", None, 2),

        BitField("rxLevC10Lo", None, 4),
        BitField("rxLevC11Hi", None, 4),

        BitField("rxLevC13Lo", None, 2),
        BitField("rxLevC12", None, 6),

        BitField("rxLevC13", None, 6),
        BitField("rxLevC14Hi", None, 2),

        BitField("rxLevC14Lo", None, 4),
        BitField("rxLevC15Hi", None, 4),

        BitField("rxLevC15Lo", None, 2),
        BitField("rxLevC16", None, 6),


        BitField("rxLevC17", None, 6),
        BitField("rxLevC18Hi", None, 2),

        BitField("rxLevC18Lo", None, 4),
        BitField("rxLevC19Hi", None, 4),

        BitField("rxLevC19Lo", None, 2),
        BitField("rxLevC20", None, 6)
    ]


# len 17
class ExtendedMeasurementFrequencyList(Packet):
    """Extended Measurement Frequency List Section 10.5.2.46"""
    name = "Extended Measurement Frequency List"
    fields_desc = [

        BitField("bit128", 0x0, 1),
        BitField("bit127", 0x0, 1),
        BitField("spare", 0x0, 1),
        BitField("seqCode", 0x0, 1),
        BitField("bit124", 0x0, 1),
        BitField("bit123", 0x0, 1),
        BitField("bit122", 0x0, 1),
        BitField("bit121", 0x0, 1),

        BitField("bitsRest", 0x0, 128)
    ]


class SuspensionCause(Packet):
    """Suspension Cause Section 10.5.2.47"""
    name = "Suspension Cause"
    fields_desc = [
        ByteField("suspVal", 0x0)
    ]


class ApduID(Packet):
    """APDU Flags Section 10.5.2.48"""
    name = "Apdu Id"
    fields_desc = [
        BitField("id", None, 4)
    ]


class ApduFlags(Packet):
    """APDU Flags Section 10.5.2.49"""
    name = "Apdu Flags"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("cr", 0x0, 1),
        BitField("firstSeg", 0x0, 1),
        BitField("lastSeg", 0x0, 1)
    ]


# len 1 to max L3 (251) (done)
class ApduData(Packet):
    """APDU Data Section 10.5.2.50"""
    name = "Apdu Data"
    fields_desc = [
        XByteField("lengthAD", None),
        # optional
    ] + [ByteField("apuInfo" + str(x), None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 250, a, self.fields_desc, 1)
        if self.lengthAD is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay
#
# 10.5.3 Mobility management information elements
#


# len 3 to L3 max (251) (done)
class NetworkName(Packet):
    """Network Name Section 10.5.3.5a"""
    name = "Network Name"
    fields_desc = [

        XByteField("lengthNN", None),

        BitField("ext", 0x1, 1),
        BitField("codingScheme", 0x0, 3),
        BitField("addCi", 0x0, 1),
        BitField("nbSpare", 0x0, 3),
        # optional
    ] + [ByteField("txtString" + str(x), None) for x in range(1, 249)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 250, a, self.fields_desc, 1)
        if self.lengthNN is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class TimeZone(Packet):
    """Time Zone  Section 10.5.3.8"""
    name = "Time Zone"
    fields_desc = [
        ByteField("timeZone", 0x0),
    ]


class TimeZoneAndTime(Packet):
    """Time Zone and Time Section 10.5.3.9"""
    name = "Time Zone and Time"
    fields_desc = [
        ByteField("year", 0x0),
        ByteField("month", 0x0),
        ByteField("day", 0x0),
        ByteField("hour", 0x0),
        ByteField("minute", 0x0),
        ByteField("second", 0x0),
        ByteField("timeZone", 0x0)
    ]


class CtsPermission(Packet):
    """CTS permission Section 10.5.3.10"""
    name = "Cts Permission"
    fields_desc = [
    ]


class LsaIdentifier(Packet):
    """LSA Identifier Section 10.5.3.11"""
    name = "Lsa Identifier"
    fields_desc = [
        ByteField("lsaID", 0x0),
        ByteField("lsaID1", 0x0),
        ByteField("lsaID2", 0x0)
    ]


#
# 10.5.4 Call control information elements
#

# 10.5.4.1 Extensions of codesets
# This is only text and no  packet

class LockingShiftProcedure(Packet):
    """Locking shift procedure Section 10.5.4.2"""
    name = "Locking Shift Procedure"
    fields_desc = [
        BitField("lockShift", 0x0, 1),
        BitField("codesetId", 0x0, 3)
    ]


class NonLockingShiftProcedure(Packet):
    """Non-locking shift procedure Section 10.5.4.3"""
    name = "Non-locking Shift Procedure"
    fields_desc = [
        BitField("nonLockShift", 0x1, 1),
        BitField("codesetId", 0x0, 3)
    ]


class AuxiliaryStates(Packet):
    """Auxiliary states Section 10.5.4.4"""
    name = "Auxiliary States"
    fields_desc = [
        XByteField("lengthAS", 0x3),
        BitField("ext", 0x1, 1),
        BitField("spare", 0x0, 3),
        BitField("holdState", 0x0, 2),
        BitField("mptyState", 0x0, 2)
    ]


# len 3 to 15
class BearerCapability(Packet):
    """Bearer capability Section 10.5.4.5"""
    name = "Bearer Capability"
    fields_desc = [

        XByteField("lengthBC", None),

        BitField("ext0", 0x1, 1),
        BitField("radioChReq", 0x1, 2),
        BitField("codingStd", 0x0, 1),
        BitField("transMode", 0x0, 1),
        BitField("infoTransCa", 0x0, 3),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("coding", None, 1),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("spare", None, 2),
                         lambda pkt: pkt.ext0 == 0),
        ConditionalField(BitField("speechVers", 0x0, 4),
                         lambda pkt: pkt.ext0 == 0),

        ConditionalField(BitField("ext2", 0x1, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("compress", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("structure", None, 2),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("dupMode", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("config", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("nirr", None, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("establi", 0x0, 1),
                         lambda pkt: pkt.ext1 == 0),

        BitField("ext3", None, 1),
        BitField("accessId", None, 2),
        BitField("rateAda", None, 2),
        BitField("signaling", None, 3),

        ConditionalField(BitField("ext4", None, 1),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("otherITC", None, 2),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("otherRate", None, 2),
                         lambda pkt: pkt.ext3 == 0),
        ConditionalField(BitField("spare1", 0x0, 3),
                         lambda pkt: pkt.ext3 == 0),

        ConditionalField(BitField("ext5", 0x1, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("hdr", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("multiFr", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("mode", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("lli", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("assig", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("inbNeg", None, 1),
                         lambda pkt: pkt.ext4 == 0),
        ConditionalField(BitField("spare2", 0x0, 1),
                         lambda pkt: pkt.ext4 == 0),

        BitField("ext6", None, 1),
        BitField("layer1Id", None, 2),
        BitField("userInf", None, 4),
        BitField("sync", None, 1),

        ConditionalField(BitField("ext7", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("stopBit", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("negoc", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("nbDataBit", None, 1),
                         lambda pkt: pkt.ext6 == 0),
        ConditionalField(BitField("userRate", None, 4),
                         lambda pkt: pkt.ext6 == 0),

        ConditionalField(BitField("ext8", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("interRate", None, 2),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("nicTX", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("nicRX", None, 1),
                         lambda pkt: pkt.ext7 == 0),
        ConditionalField(BitField("parity", None, 3),
                         lambda pkt: pkt.ext7 == 0),

        ConditionalField(BitField("ext9", None, 1),
                         lambda pkt: pkt.ext8 == 0),
        ConditionalField(BitField("connEle", None, 2),
                         lambda pkt: pkt.ext8 == 0),
        ConditionalField(BitField("modemType", None, 5),
                         lambda pkt: pkt.ext8 == 0),

        ConditionalField(BitField("ext10", None, 1),
                         lambda pkt: pkt.ext9 == 0),
        ConditionalField(BitField("otherModemType", None, 2),
                         lambda pkt: pkt.ext9 == 0),
        ConditionalField(BitField("netUserRate", None, 5),
                         lambda pkt: pkt.ext9 == 0),

        ConditionalField(BitField("ext11", None, 1),
                         lambda pkt: pkt.ext10 == 0),
        ConditionalField(BitField("chanCoding", None, 4),
                         lambda pkt: pkt.ext10 == 0),
        ConditionalField(BitField("maxTrafficChan", None, 3),
                         lambda pkt: pkt.ext10 == 0),

        ConditionalField(BitField("ext12", None, 1),
                         lambda pkt: pkt.ext11 == 0),
        ConditionalField(BitField("uimi", None, 3),
                         lambda pkt: pkt.ext11 == 0),
        ConditionalField(BitField("airInterfaceUserRate", None, 4),
                         lambda pkt: pkt.ext11 == 0),

        ConditionalField(BitField("ext13", 0x1, 1),
                         lambda pkt: pkt.ext12 == 0),
        ConditionalField(BitField("layer2Ch", None, 2),
                         lambda pkt: pkt.ext12 == 0),
        ConditionalField(BitField("userInfoL2", 0x0, 5),
                         lambda pkt: pkt.ext12 == 0)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 15, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthBC is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


class CallControlCapabilities(Packet):
    """Call Control Capabilities Section 10.5.4.5a"""
    name = "Call Control Capabilities"
    fields_desc = [
        XByteField("lengthCCC", 0x3),
        BitField("spare", 0x0, 6),
        BitField("pcp", 0x0, 1),
        BitField("dtmf", 0x0, 1)
    ]


class CallState(Packet):
    """Call State Section 10.5.4.6"""
    name = "Call State"
    fields_desc = [
        BitField("codingStd", 0x0, 2),
        BitField("stateValue", 0x0, 6)
    ]


# len 3 to 43
class CalledPartyBcdNumber(Packet):
    """Called party BCD number Section 10.5.4.7"""
    name = "Called Party BCD Number"
    fields_desc = [
        XByteField("lengthCPBN", None),
        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("nbPlanId", 0x0, 4),
        # optional
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 80)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 42, a, self.fields_desc, 1)
        if self.lengthCPBN is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to 23
class CalledPartySubaddress(Packet):
    """Called party subaddress Section 10.5.4.8"""
    name = "Called Party Subaddress"
    fields_desc = [
        XByteField("lengthCPS", None),
        # optional
        BitField("ext", None, 1),
        BitField("subAddr", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo" + str(x), None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 23, a, self.fields_desc, 1)
        if self.lengthCPS is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 3 to 14
class CallingPartyBcdNumber(Packet):
    """Called party subaddress Section 10.5.4.9"""
    name = "Called Party Subaddress"
    fields_desc = [
        XByteField("lengthCPBN", None),
        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("nbPlanId", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", None, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", None, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", 0x0, 2),
                         lambda pkt: pkt.ext == 0),
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 20)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 13, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthCPBN is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


# len 2 to 23
class CallingPartySubaddress(Packet):
    """Calling party subaddress  Section 10.5.4.10"""
    name = "Calling Party Subaddress"
    fields_desc = [
        XByteField("lengthCPS", None),
        # optional
        BitField("ext1", None, 1),
        BitField("typeAddr", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo" + str(x), None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 22, a, self.fields_desc, 1)
        if self.lengthCPS is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 4 to 32
class Cause(Packet):
    """Cause Section 10.5.4.11"""
    name = "Cause"
    fields_desc = [

        XByteField("lengthC", None),

        BitField("ext", 0x1, 1),
        BitField("codingStd", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("location", 0x0, 4),

        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("recommendation", 0x1, 7),
                         lambda pkt: pkt.ext == 0),
        # optional
        BitField("ext2", None, 1),
        BitField("causeValue", None, 7),
    ] + [ByteField("diagnositc" + str(x), None) for x in range(0, 27)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(3, 31, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthC is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


class ClirSuppression(Packet):
    """CLIR suppression Section 10.5.4.11a"""
    name = "Clir Suppression"
    fields_desc = [
    ]


class ClirInvocation(Packet):
    """CLIR invocation Section 10.5.4.11b"""
    name = "Clir Invocation"
    fields_desc = [
    ]


class CongestionLevel(Packet):
    """Congestion level Section 10.5.4.12"""
    name = "Congestion Level"
    fields_desc = [
        BitField("notDef", 0x0, 4)  # not defined by the std
    ]


# len 3 to 14
class ConnectedNumber(Packet):
    """Connected number Section 10.5.4.13"""
    name = "Connected Number"
    fields_desc = [

        XByteField("lengthCN", None),

        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("typePlanId", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", None, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", None, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", None, 2),
                         lambda pkt: pkt.ext == 0),
    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 20)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 13, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthCN is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


# len 2 to 23
class ConnectedSubaddress(Packet):
    """Connected subaddress Section 10.5.4.14"""
    name = "Connected Subaddress"
    fields_desc = [

        XByteField("lengthCS", None),
        # optional
        BitField("ext", None, 1),
        BitField("typeOfSub", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),
    ] + [ByteField("subInfo" + str(x), None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 22, a, self.fields_desc, 1)
        if self.lengthCS is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to L3 (251) (done)
class Facility(Packet):
    """Facility Section 10.5.4.15"""
    name = "Facility"
    fields_desc = [
        XByteField("lengthF", None),
        # optional
    ] + [ByteField("facilityInfo" + str(x), None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(7, 250, a, self.fields_desc, 1)
        if self.lengthF is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# len 2 to 5
class HighLayerCompatibility(Packet):
    """High layer compatibility Section 10.5.4.16"""
    name = "High Layer Compatibility"
    fields_desc = [

        XByteField("lengthHLC", None),
        # optional
        BitField("ext", None, 1),
        BitField("codingStd", None, 2),
        BitField("interpret", None, 3),
        BitField("presMeth", None, 2),

        BitField("ext1", None, 1),
        BitField("highLayerId", None, 7),

        ConditionalField(BitField("ext2", 0x1, 1),
                         lambda pkt: pkt.ext1 == 0),
        ConditionalField(BitField("exHiLayerId", 0x0, 7),
                         lambda pkt: pkt.ext1 == 0),
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 4, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthHLC is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay
#
# 10.5.4.16.1           Static conditions for the high layer
# compatibility IE contents
#


class KeypadFacility(Packet):
    """Keypad facility Section 10.5.4.17"""
    name = "Keypad Facility"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("keyPadInfo", 0x0, 7)
    ]


# len 2 to 15
class LowLayerCompatibility(Packet):
    """Low layer compatibility Section 10.5.4.18"""
    name = "Low Layer Compatibility"
    fields_desc = [

        XByteField("lengthLLC", None),
        # optional
    ] + [ByteField("rest" + str(x), None) for x in range(0, 13)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 14, a, self.fields_desc, 1)
        if self.lengthLLC is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class MoreData(Packet):
    """More data Section 10.5.4.19"""
    name = "More Data"
    fields_desc = [
    ]


class NotificationIndicator(Packet):
    """Notification indicator Section 10.5.4.20"""
    name = "Notification Indicator"
    fields_desc = [
        BitField("ext1", 0x1, 1),
        BitField("notifDesc", 0x0, 7)
    ]


class ProgressIndicator(Packet):
    """Progress indicator Section 10.5.4.21"""
    name = "Progress Indicator"
    fields_desc = [
        XByteField("lengthPI", 0x2),
        BitField("ext", 0x1, 1),
        BitField("codingStd", 0x0, 2),
        BitField("spare", 0x0, 1),
        BitField("location", 0x0, 4),
        BitField("ext1", 0x1, 1),
        BitField("progressDesc", 0x0, 7)
    ]


class RecallType(Packet):
    """Recall type $(CCBS)$  Section 10.5.4.21a"""
    name = "Recall Type $(CCBS)$"
    fields_desc = [
        BitField("spare", 0x0, 5),
        BitField("recallType", 0x0, 3)
    ]


# len 3 to 19
class RedirectingPartyBcdNumber(Packet):
    """Redirecting party BCD number  Section 10.5.4.21b"""
    name = "Redirecting Party BCD Number"
    fields_desc = [

        XByteField("lengthRPBN", None),

        BitField("ext", 0x1, 1),
        BitField("typeNb", 0x0, 3),
        BitField("numberingPlan", 0x0, 4),
        # optional
        ConditionalField(BitField("ext1", 0x1, 1),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("presId", 0x0, 2),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("spare", 0x0, 3),
                         lambda pkt: pkt.ext == 0),
        ConditionalField(BitField("screenId", 0x0, 2),
                         lambda pkt: pkt.ext == 0),

    ] + [
        BitField("nbDigit" + (str(x + 1) if x % 2 != 0 else str(x - 1)), None, 4) for x in range(1, 31)
    ]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 18, a, self.fields_desc, 1)
        if res[0] != 0:
            p = p[:-res[0]]
        if self.lengthRPBN is None:
            p = chb(len(p) - 1) + p[1:]
        return p + pay


# length 2 to 23
class RedirectingPartySubaddress(Packet):
    """Redirecting party subaddress  Section 10.5.4.21c"""
    name = "Redirecting Party BCD Number"
    fields_desc = [

        XByteField("lengthRPS", None),
        # optional
        BitField("ext", None, 1),
        BitField("typeSub", None, 3),
        BitField("oddEven", None, 1),
        BitField("spare", None, 3),

    ] + [ByteField("subInfo" + str(x), None) for x in range(0, 20)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 22, a, self.fields_desc, 1)
        if self.lengthRPS is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class RepeatIndicator(Packet):
    """Repeat indicator Section 10.5.4.22"""
    name = "Repeat Indicator"
    fields_desc = [
        BitField("repeatIndic", 0x0, 4)
    ]


# no upper length min 2(max for L3) (251)
class SetupContainer(Packet):
    """SETUP Container $(CCBS)$ Section 10.5.4.22b"""
    name = "Setup Container $(CCBS)$"
    fields_desc = [
        XByteField("lengthSC", None),
        # optional
    ] + [ByteField("mess" + str(x), None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 250, a, self.fields_desc, 1)
        if self.lengthSC is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class Signal(Packet):
    """Signal Section 10.5.4.23"""
    name = "Signal"
    fields_desc = [
        ByteField("sigValue", 0x0)
    ]


# length 2 to max for L3 message (251)
class SsVersionIndicator(Packet):
    """SS Version Indicator  Section 10.5.4.24"""
    name = "SS Version Indicator"
    fields_desc = [
        XByteField("lengthSVI", None),
        # optional
    ] + [ByteField("info" + str(x), None) for x in range(1, 250)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(1, 250, a, self.fields_desc, 1)
        if self.lengthSVI is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


# length 3 to 35 or 131
class UserUser(Packet):
    """User-user Section 10.5.4.25"""
    name = "User-User"
    fields_desc = [

        XByteField("lengthUU", None),  # dynamic length of field depending
        # of the type of message
        # let user decide which length he
        # wants to take
        # => more fuzzing options
        ByteField("userUserPD", 0x0),
        # optional
    ] + [ByteField("userUserInfo" + str(x), None) for x in range(1, 132)]

    def post_build(self, p, pay):
        a = [getattr(self, fld.name) for fld in self.fields_desc]
        res = _adapt(2, 133, a, self.fields_desc, 1)
        if self.lengthUU is None:
            p = chb(res[1]) + p[1:]
        if res[0] != 0:
            p = p[:-res[0]]
        return p + pay


class AlertingPattern(Packet):
    """Alerting Pattern 10.5.4.26"""
    name = "Alerting Pattern"
    fields_desc = [
        XByteField("lengthAP", 0x3),
        BitField("spare", 0x0, 4),
        BitField("alertingValue", 0x0, 4)
    ]


class AllowedActions(Packet):
    """Allowed actions $(CCBS)$ Section 10.5.4.26"""
    name = "Allowed Actions $(CCBS)$"
    fields_desc = [
        XByteField("lengthAP", 0x3),
        BitField("CCBS", 0x0, 1),
        BitField("spare", 0x0, 7)
    ]


#
# 10.5.5 GPRS mobility management information elements
#


class AttachType(Packet):
    """Attach type Section 10.5.5.2"""
    name = "Attach Type"
    fields_desc = [
        BitField("spare", 0x0, 1),
        BitField("type", 0x1, 3)
    ]

```

### Doc & TODO (if someone wants to fix the module)

```
### STATUS ###

This file was originaly located as http://0xbadcab1e.lu/scapy_gsm_um-howto.txt
but has been deleted since its creation. It was retrieved using the wayback machine
http://archive.org/web/

--> It should be used to create tests for the contrib/gsm_um module, which needs first
to be fixed on Python 3.

##############

This files shows how to create and send packets using scapy gsm-um addon. The
packets are taken out of [0]. The frames number at the top of each example are
a reference to the pcap capture.

                                                         +-------------------+
                                                         |- Examples         |
                   Scapy GSM um Addon                    |- Sending messages |
                   ==================                    |- Contact          |
                                                         +-------------------+
        
- Examples:
  ---------

Frame 28
>>> a=immediateAssignment()
>>> a.channelTyp=12; a.tn=2; tsc=6; a.h=1; a.hsn=41; a.tsc=6; a.t1=4
>>> a.t2=0xf; a.t3Lo=1; a.ra=0x49; a.timingVal=1; a.maC64=0x;
>>> a.l2pLength=12
>>> hexdump(a)
0000   31 06 3F 00 62 D0 29 49  20 2F 01 01 03            1.?.b.)I /...

Frame 34
>>> a=cmServiceRequest()
>>> a.keySeq=3; a.serviceType=1
>>> a.revisionLvl=1; a.esInd=1; a.rfPowerCap=3; a.ssScreenInd=1;
>>> a.smCaPabi=1; a.fc=1; a.cm3=1; a.a52=1; a.idDigit1=0xf;
>>> a.idDigit2_1=2; a.idDigit2=0xe; a.idDigit3_1=4; a.idDigit3=8;
>>> a.idDigit4_1=4; a.idDigit4=1; a.idDigit5_1=1; a.idDigit5=5;
>>> hexdump(a)
0000   05 24 31 03 33 19 81 05  F4 2E 48 41 15            .$..3.....HA.

Frame 35
>>> a=classmarkChange(MobileStationClassmark3_presence=1)
>>> a.revisionLvl=1; a.esInd=1; a.rfPowerCap=3; a.ssScreenInd=1
>>> a.smCaPabi=1; a.fc=1; a.cm3=1; a.a52=1; a.byte2=0x60; a.byte3=0x14
>>> hexdump(a)
0000   06 16 03 33 19 81 20 60  14 00 00 00 00 00 00 00   ...3.. `........
0010   00 00 00 00                                        ....

Frame 36
>>> a=cipheringModeCommand()
>>> a.sc=1; a.cr=1
>>> hexdump(a)
0000   06 35 00 11                                        .5..

Frame 39
>>> a=releaseCompleteMsToNet(Cause_presence=1)
>>> a.codingStd=3; a.ext2=1; a.causeValue=16
>>> a.mesType=0x6a # due to the sequence number we need to change this
>>> hexdump(a)
0000   03 6A 08 02 E0 90                                  .j....

Frame 40
>>> a=cipheringModeComplete(MobileId_presence=1)
>>> a.idDigit1=3; a.typeOfId=3
>>> a.idDigit2_1=0; a.idDigit2=5; a.idDigit3_1=3; a.idDigit3=1
>>> a.idDigit4_1=2; a.idDigit4=7; a.idDigit5_1=6; a.idDigit5=0
>>> a.idDigit6_1=4;a.idDigit6=5;
>>> a.idDigit7_1=5;a.idDigit7=6; a.idDigit8_1=1;  a.idDigit8=4
>>> a.idDigit9_1=0xf; a.idDigit9=0
>>> hexdump(a)
0000   06 32 17 09 33 05 31 27  60 45 56 14 F0            .2..3.1'`EV..

Frame 45
a=tmsiReallocationCommand()
>>> a.oddEven=1
>>> a.typeOfId=4
>>> a.idDigit2_1=2; a.idDigit2=e; a.idDigit3_1=4; a.idDigit3=8 ;
>>> a.idDigit4_1=e ; a.idDigit4=5 ; a.idDigit5_1=e ; a.idDigit5=0
>>> a.mccDigit2=0x4; a.mccDigit1=2; a.mccDigit3=6; a.mncDigit1=0
>>> a.mncDigit3=0xf; a.mncDigit2=0x3; a.lac1=0x0; a.lac2=0x4
>>> a.idDigit1=0xf; a.oddEven=0
>>> hexdump(a)
0000   05 1A 42 F6 30 00 04 05  F4 2E 48 E5 E0            ..B.0.....H..

Frame 47
>>> a=callProceeding()
>>> a.ti=8
>>> hexdump(a)
0000   83 02                                              ..

Frame 48
>>> a=tmsiReallocationComplete()
>>> hexdump(a)
0000   05 1B                                              ..

Frame 51
>>> a=immediateAssignment()
>>> a.tsc=6; a.tn=5; a.channelTyp=1; a.codingStd=3;
>>> a.location=0xa; a.progressDesc=8; a.arfcnLow=0xff
>>> a.arfcnHigh=3; a.powerLvl=5
>>> hexdump(a)
0000   06 2E 0D C3 FF 05                                  ......

Frame 55
>>> a=assignmentComplete()
>>> hexdump(a)
0000   06 29 00                                           .).

Frame 60
>>> a=progress()
>>> a.ti=8; a.codingStd=3; a.location=0xa; a.progressDesc=8
>>> hexdump(a)
0000   83 03 02 EA 88                                     .....

Frame 65
>>> a=alertingNetToMs(ProgressIndicator_presence=1)
>>> a.ti=8; a.codingStd=3; a.location=0xa; a.progressDesc=8
>>> hexdump(a)
0000   83 01 1E 02 EA 88                                  ......

Frame 68
>>> a=connectNetToMs()
>>> a.ti=8
>>> hexdump(a)
0000   83 07                                              ..

Frame 70
>>> a=connectAcknowledge()
>>> a.mesType=0x4f
>>> hexdump(a)
0000   03 4F                                              .O

Frame 88
>>> a=disconnectMsToNet()
>>> a.codingStd=3; a.ext2=1; a.causeValue=16
>>> hexdump(a)
0000   03 25 02 E0 90                                     .%...

Frame 90
>>> a=systemInformationType6()
>>> a.ciValue1=0x40; a.ciValue2=0x5c
>>> a.mccDigit2=4; a.mccDigit1=2; a.mncDigit3=0xf; a.mccDigit3=6;
>>> a.mncDigit2=3; a.mncDigit1=0; a.lac1=0; a.lac2=4
>>> a.l2pLength=11; a.nccPerm=0xc; a.dtx=1; a.rLinkTout=4
>>> hexdump(a)
0000   2D 06 1e 40 5C 42 F6 30  00 04 14 0C               -.6@\B.0....

Frame 91
>>> a=releaseNetToMs()
>>> a.ti=8; a.codingStd=3; a.ext2=1; a.causeValue=16
>>> hexdump(a)
0000   83 2D 08 02 E0 90                                  .-....

Frame 94
>>> a=measurementReport()
>>> a.baUsed=1; a.dtxUsed=1; a.rxLevFull=39;
>>> a.noNcellHi=1; a.rxlevC1=38;
>>> a.bcchC1=4; a.bsicC1Hi=2; a.rxlevC2=18;
>>> a.bsicC1Hi=1; a.bsicC3Lo=1; a.bsicC3Hi=3;
>>> a.bcchC5Hi=10; a.bsicC6=29; a.bsicC5=18; a.bcchC6Hi=2;
>>> a.rxlevC6Lo=18; a.bcchC6Lo=2; a.bcchC6Hi=2;
>>> a.rxlevC5Lo=3; a.rxlevC5Hi=1; a.bsicC4=25;
>>> a.bcchC4=0xa; a.bcchC2=3;
>>> a.bsicC2Lo=0; a.bcchC2=3; a.bsicC1Hi=1;
>>> a.bsicC3Lo=25; a.bsicC1Hi=1; a.bscicC2Hi=6; a.rxLevSub=39;
>>> a.noNcellLo=2; a.rxlevC4Lo=3;
>>> a.rxlevC3Lo=3; a.bcchC3=12; a.bcchC5Hi=3;
>>> a.bsicC1Hi=2; a.bsicC2Hi=1
>>> hexdump(a)
0000   06 15 E7 27 01 A6 22 12  0D 06 D8 CB 6A 65 33 24   ...'..".....je3$
0010   92 5D                                              .]

Frame 129
>>> a=systemInformationType3()
>>> a.mccDigit2=4; a.mccDigit1=2; a.mncDigit3=0xf; a.mccDigit3=6;
>>> a.mncDigit2=3; a.mncDigit1=0; a.lac1=0; a.lac2=04
>>> a.ciValue2=0x5c; a.t3212=0xc8; a.bsPaMfrms=7; a.dtx=1
>>> a.rLinkTout=4; a.cellReselect=4; a.msTxPwrMax=5; a.neci=1;
>>> a.maxRetrans=1; a.txInteger=9; a.re=1; a.byte1=0x80; a.byte5=0x1b
>>> hexdump(a)
0000   49 06 1B 40 5C 42 F6 30  00 04 48 07 C8 14 85 40   I..@\B.0..H....@
0010   65 00 00 80 00 00 00 1B                            e.......

Frame 158
>>> a=pagingRequestType1()
>>> a.idDigit1=0xf; a.l2pLength=5
>>> hexdump(a)
0000   15 06 21 00 01 F0                                  ..!...

Frame 168
>>> a=pagingRequestType1()
>>> a.idDigit1=0xf; a.typeOfId=4; a.idDigit2_1=0x2; a.idDigit2=0xe
>>> a.idDigit3_1=4; a.idDigit3=8; a.idDigit4=0xd; a.idDigit5=0xf
>>> a.l2pLength=9
>>> hexdump(a)
0000   25 06 21 00 05 F4 2E 48  0D 0F                     %.!....H..

Frame 179
>>> a=systemInformationType4()
>>> a.maxRetrans=1; a.txInteger=0x9; a.cellBarrAccess=0x0; a.re=1
>>> a.cellReselect=0x4; a.msTxPwrMax=0x5; a.neci=1; a.rxlenAccMin=0
>>> a.lac1=0x0; a.lac2=0x4; a.mccDigit2=0x4; a.mccDigit1=0x2
>>> a.mncDigit3=0xf; a.mccDigit3=0x3; a.l2pLength=12
>>> hexdump(a)
0000   31 06 1C 42 F6 30 00 04  85 40 65 00 00            1..B.0...@e..

Frame 179
>>> a=systemInformationType4()
>>> a.maxRetrans=1; a.txInteger=0x9; a.cellBarrAccess=0x0; a.re=1
>>> a.cellReselect=0x4; a.msTxPwrMax=0x5; a.neci=1; a.rxlenAccMin=0
>>> a.lac1=0x0; a.lac2=0x4; a.mccDigit2=0x4; a.mccDigit1=0x2
>>> a.mncDigit3=0xf; a.mccDigit3=0x3; a.l2pLength=12
>>> hexdump(a)
0000   31 06 1C 42 F6 30 00 04  85 40 65 00 00            1..B.0...@e..

[0]: http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=view&target=gsm_call_1525.xml


- Sending messages:
  -----------------
Use the sendum() method. It profides 3 ways to send messages over your prefered hardware.
  * method 1:
    UDP Socket (use parameter 0 (default)) Default port is 28670 (default for OpenBTS).
  * method 2:
    Unix Domain Socket (use parameter 1) Default file '/tmp/osmoL'.
  * method 3:
    TCP Socket (use parameter 2) Default port is 43797.

Example: 
>>> semdum(systemInformationType4(),1) 
if you want to send your layer3 message over a Unix Domain Socket.


- Contact:
  --------
Bugs, feedback: <k@0xbadcab1e.lu>
```