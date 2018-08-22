#!/usr/bin/env python3
#-*- coding: utf-8 -*-


import asyncio
import async_timeout
import aiodns
import os
import sys
import socket
import struct
import time
import shelve


#timer selection
if sys.platform == "win32":
    default_timer = time.clock
else:
    default_timer = time.time

#for icmp echo request function code must be 8
ICMP_ECHO_REQUEST = 8

input_message = '''
================Send to device================
          
                PLC     : 1
                wolke   : 2
                xb4jet  : 3
                server  : 4
                HMI     : 5
                Exit    : 0
                
                Please input your choice (0 : 5) : '''


def raw_socket_free_protokol(dst_addr, src_addr, ethertype, payload, checksum):
    """
    this function send free protocol message
    """
    try:
        s = socket(AF_PACKET, SOCK_RAW)
        s.bind(("eth1", 0))
        s.send(dst_addr + src_addr + ethertype + payload + checksum)

    except Exception as e:
        print("Error {}".format(e) )

def checksum(buffer):
    """
    this function calculate checksum for sending message
    """
    sum = 0
    count_to = (len(buffer) / 2) * 2
    count = 0

    while count < count_to:
        this_val = buffer[count + 1] * 256 + buffer[count]
        sum += this_val
        count += 2

    if count_to < len(buffer):
        sum += buffer[len(buffer) - 1]

    sum = (sum >> 16) + (sum & 0xffff)
    sum += sum >> 16
    answer = ~sum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


async def receive_one_ping(my_socket, id_, timeout):
    """
    this function receive the ping from the socket
    """
    loop = asyncio.get_event_loop()

    try:
        with async_timeout.timeout(timeout):
            rec_packet = await loop.sock_recv(my_socket, 1024)
            time_received = default_timer()
            icmp_header = rec_packet[20:28]

            type, code, checksum, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

            if type != 8 and packet_id == id_:
                bytes_in_double = struct.calcsize("d")
                time_sent = struct.unpack("d", rec_packet[28:28 + bytes_in_double])[0]

                return time_received - time_sent

    except asyncio.TimeoutError:
        raise TimeoutError("Ping timeout")


async def send_one_ping(my_socket, dest_addr, id_, timeout):
    """
    this function send one ping to the given address "dest_addr"
    """
    try:
        resolver = aiodns.DNSResolver(timeout=timeout, tries=1)
        dest_addr = await resolver.gethostbyname(dest_addr, socket.AF_INET)
        dest_addr = dest_addr.addresses[0]

    except aiodns.error.DNSError:
        raise ValueError("Unable to resolve host")

    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, id_, 1)
    bytes_in_double = struct.calcsize("d")
    data = (192 - bytes_in_double) * "Q"
    data = struct.pack("d", default_timer()) + data.encode("ascii")

    my_checksum = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id_, 1)
    packet = header + data

    loop = asyncio.get_event_loop()
    await loop.sock_connect(my_socket, (dest_addr, 1))
    await loop.sock_sendall(my_socket, packet)


async def ping(dest_addr, timeout=10):
    """
    this function returns either the delay (in seconds) or raises an exception.
    """
    icmp = socket.getprotobyname("icmp")

    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        my_socket.setblocking(0)

    except OSError as e:
        msg = e.strerror

        if e.errno == 1:
            # Operation not permitted
            msg += (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )

            raise OSError(msg)

        raise

    my_id = os.getpid() & 0xFFFF

    await send_one_ping(my_socket, dest_addr, my_id, timeout)
    delay = await receive_one_ping(my_socket, my_id, timeout)
    my_socket.close()

    return delay


async def verbose_ping(dest_addr, timeout=2, count=3):
    """
    this function call function ping n times (n = count)
    """
    for i in range(count):
        try:
            delay = await ping(dest_addr, timeout)
        except Exception as e:
            print('<>' * 60 + ' Exeption')
            print("%s failed: %s" % (dest_addr, str(e)))
            print('=' * 150)
            break

        delay *= 1000
        print("%s get ping in %0.4fms" % (dest_addr, delay))


# when executing aio_ping.py file
if __name__ == "__main__":
    tasks = []
    loop = asyncio.get_event_loop()

    try:
        s = shelve.open('configuration_file.dat')
        for ip_n in (s["ip_list"]):
            tasks.append(asyncio.ensure_future(verbose_ping(ip_n, count = 100)))
        '''     <><><><><>  in progress  <><><><><>
        
        # no records in configuration file
        # waiting for permission
        
        dst_addr = s["dst_addr"]
        src_addr = s["src_addr"]
        ethertype = s["ethertype"]
        payload = s["payload"]
        checksum = s["checksum"]
        '''
        s.close()
    except Exception as err:
        print("Error {}".format(err))

    loop.run_until_complete(asyncio.gather(*tasks))

    '''     <><><><><>  in progress  <><><><><>
    
    user_choice = int(input(input_message))
    if (user_choice > 0 and user_choice < 6):
        raw_socket_free_protokol(
                                dst_addr[user_choice],
                                src_addr[user_choice],
                                ethertype[user_choice],
                                payload[user_choice],
                                checksum[user_choice]
        )
    else:
        input("===============================  Goodbye !!!  ===============================")
    '''