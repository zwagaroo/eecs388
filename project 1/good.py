#!/usr/bin/python3
# coding: latin-1
blob = """
                �?�7�h�*����A��ŀ�7FNU�R2|��2���<L���;�E �*H_x��{�i:�e%��ݘ�(HC,�hl��K%��;u:l��K`��(B�
rȣ_�k���m! GB�`��`B/b�R�
"""
if(blob.encode() == b'\nr\xc3\x88\xc2\xa3_\xc3\xa7\xc2\x91k\xc2\xb1\xc2\xa9\xc2\xbdm\x07!' ):
    print("Use SHA-256 instead!")
else:
    print("MD5 is perfectly secure!")