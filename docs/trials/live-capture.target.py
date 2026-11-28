#!/usr/bin/env python3
"""A stand-in for a game, for trying a live capture: a process that holds a
player record in memory and shows part of it on screen.

    uv run --locked docs/trials/live-capture.target.py

It prints its process id, where the record is and how long it is, and what a
player would see: the hit points exactly, the armor rounded. Enter changes the
values. The record's layout is in the source below; an agent working from a
capture is not given it.
"""
import ctypes
import os
import random


class Player(ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_char * 4),
        ("hp", ctypes.c_uint32),
        ("armor", ctypes.c_float),
        ("ammo", ctypes.c_int16),
        ("x", ctypes.c_double),
        ("name", ctypes.c_char * 16),
    ]


player = Player(b"PLYR", 73, 21.25, 12, 1024.5, b"Gordon")
print(f"pid {os.getpid()}   record at {ctypes.addressof(player):#x}, {ctypes.sizeof(player)} bytes")
while True:
    print(f"HP {player.hp}   ARMOR {round(player.armor)}   AMMO {player.ammo}")
    input("Enter for the next moment, Ctrl-C to stop ")
    player.hp = random.randint(1, 100)
    player.armor = random.uniform(0, 100)
    player.ammo = random.randint(0, 30)
