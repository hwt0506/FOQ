from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import numpy as np
import socket
from copy import deepcopy
import random
import struct
import pickle
import math
import subprocess
import re

def server_receive(client_socket, length): #int数组版
    '''
    data = b""
    client_socket.settimeout(5.0)  # 设置超时为5秒
    while True:
        try:
            packet = client_socket.recv(4096)
            if not packet:
                break
            data += packet
        except socket.timeout:
            print("Receiving data timed out.")
            break
    received_data = pickle.loads(data)
    '''
    data = client_socket.recv(length)
    received_data = [int.from_bytes(data[i:i+32], byteorder='big') for i in range(0, 64, 32)]
    return received_data

def server_send(client_socket, arr): #int数组版
    # packed_data = pickle.dumps(arr)
    packed_data = b''.join(x.to_bytes(32, byteorder='big') for x in arr)
    client_socket.sendall(packed_data)
    
def server_receive_one(client_socket, length): #int数组版
    data = client_socket.recv(length)
    a = int(data)
    return a

def server_send_one(client_socket, arr): #int数组版
    client_socket.sendall(str(arr).encode()) 
    
    
#exchage XOR shares of array A
#path a[M]
#value beta

def Lsb(x):
    return x & 1

def fss_base(M, path, beta): # M = levelCount-1
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()    
    '''
    mask = server_receive(client_socket, 1024)
    '''
    Sa_0 = get_random_bytes(16)
    # MPC
    Ta_0 = server_receive_one(client_socket, 1024)

    # 建立两个初始化为0的二维数组，各M+1行且第i行有2**i个元素
    Sa = [[0] *(2**i) for i in range(M+1)]
    Sa_ = deepcopy(Sa)
    Ta = deepcopy(Sa) 
    Tb = deepcopy(Sa) 
    theta = [0] * (M+1)
    tao = [[0] * (2) for i in range(M+1)]
    Za = deepcopy(tao) 
    Zb = deepcopy(tao) 
    Ya = [0] * (2**M)
    a = [0] + path[:M] 

    Sa[0][0] = int.from_bytes(Sa_0, byteorder='big')
    Sa_[0][0] = int.from_bytes(Sa_0, byteorder='big')
    #Sa[0][0] = Sa_0
    Ta[0][0] = Ta_0
    #Ta[0][0] = int.from_bytes(Ta_0, byteorder='big')
    key = b'\xd0\x16\x01\x0c,\xb0\xfa\xcd\xc6\xfdd\x11I$I('
    # ctr = Counter.new(128, initial_value=42)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\xc7\xc9\n/\xf1\xf4\xe4\xcf')
    for j in range(1, M+1):   #range[1, M]
        for jx in range(0, 2**(j-1)):            
            plaintext = Sa_[j-1][jx].to_bytes((Sa_[j-1][jx].bit_length() + 7) // 8, byteorder='big')
            Sa[j][2*jx] = int.from_bytes(cipher.encrypt(plaintext), byteorder='big')
            Sa[j][2*jx+1] = int.from_bytes(cipher.encrypt(plaintext), byteorder='big')
            Za[j][0]= Za[j][0] ^ Sa[j][2*jx]
            Za[j][1]= Za[j][1] ^ Sa[j][2*jx+1]
        
        Zb[j] = server_receive(client_socket, 4096)
        server_send(client_socket, Za[j])

        #MPC
        theta[j] = Za[j][1^a[j]] ^ Zb[j][1^a[j]]
        tao[j][0] = Lsb(Za[j][0]) ^ Lsb(Zb[j][0]) ^ a[j] ^ 1
        tao[j][1] = Lsb(Za[j][1]) ^ Lsb(Zb[j][1]) ^ a[j]
        
        # theta[j], tao[j][0], tao[j][1] = mpc_theta_tao(Za[j], j)
        
        for jx in range(0, 2**j):
            temp = math.floor(jx/2)
            Sa_[j][jx] = Sa[j][jx]
            Ta[j][jx] = Lsb(Sa[j][jx])
            if Ta[j-1][temp]:
                Sa_[j][jx] ^= theta[j]
                Ta[j][jx] ^= tao[j][Lsb(jx)]

    #MPC
    Ga = Za[M][a[M]] ^ Zb[M][a[M]] ^ theta[M] ^ beta
    
    # beta = mpc_output_deta(option)
    # Ga = mpc_xor_gama(Za[M], M, theta[M], beta)
    
    for jx in range(0, 2**M):
        Ya[jx] = Sa_[M][jx]
        if Ta[M][jx]:
            Ya[jx] ^= Ga
            
    client_socket.close()
    server_socket.close()

    return Ta, Ya

def fss_multi(M, path, deta):  #beta有levelCount-1个元素

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()    
    '''
    mask = server_receive(client_socket, 1024)
    '''
    Sa_0 = get_random_bytes(16)
    # MPC
    Ta_0 = server_receive_one(client_socket, 1024)

    # 建立两个初始化为0的二维数组，各M+1行且第i行有2**i个元素
    Sa = [[0] *(2**i) for i in range(M+1)]
    Sa_ = deepcopy(Sa)
    Ta = deepcopy(Sa) 
    Tb = deepcopy(Sa) 
    theta = [0] * (M+1)
    tao = [[0] * (2) for i in range(M+1)]
    Za = deepcopy(tao) 
    Zb = deepcopy(tao) 
    Ya = deepcopy(Sa)
    Ga = [0]*(M+1)
    a = [0] + path[:M] 
    beta = [0] + deta[:M]
    
    Sa[0][0] = int.from_bytes(Sa_0, byteorder='big')
    Sa_[0][0] = int.from_bytes(Sa_0, byteorder='big')
    #Sa[0][0] = Sa_0
    Ta[0][0] = Ta_0
    #Ta[0][0] = int.from_bytes(Ta_0, byteorder='big')
    key = b'\xd0\x16\x01\x0c,\xb0\xfa\xcd\xc6\xfdd\x11I$I('
    # ctr = Counter.new(128, initial_value=42)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\xc7\xc9\n/\xf1\xf4\xe4\xcf')
    for j in range(1, M+1):   #range[1, M]
        for jx in range(0, 2**(j-1)):            
            plaintext = Sa_[j-1][jx].to_bytes((Sa_[j-1][jx].bit_length() + 7) // 8, byteorder='big')
            Sa[j][2*jx] = int.from_bytes(cipher.encrypt(plaintext), byteorder='big')
            Sa[j][2*jx+1] = int.from_bytes(cipher.encrypt(plaintext), byteorder='big')
            Za[j][0]= Za[j][0] ^ Sa[j][2*jx]
            Za[j][1]= Za[j][1] ^ Sa[j][2*jx+1]
        
        Zb[j] = server_receive(client_socket, 4096)
        server_send(client_socket, Za[j])
        
        # MPC
        theta[j] = Za[j][1^a[j]] ^ Zb[j][1^a[j]]
        Ga[j] = Za[j][a[j]] ^ Zb[j][a[j]] ^ theta[j] ^ beta[j]        
        
        # theta[j], tao[j][0], tao[j][1], Ga[j] = mpc_xor_theta_gama(Za[j], level)
        
        for jx in range(0, 2**j):
            temp = math.floor(jx/2)
            Sa_[j][jx] = Sa[j][jx]
            Ta[j][jx] = Lsb(Sa[j][jx])
            if Ta[j-1][temp]:
                Sa_[j][jx] ^= theta[j]
                Ta[j][jx] ^= tao[j][Lsb(jx)]

        for jx in range(0, 2**j):
            Ya[j][jx] = Sa_[j][jx]
            if Ta[j][jx]:
                Ya[j][jx] ^= Ga[j]
        
    client_socket.close()
    server_socket.close()

    return Ta, Ya

M = 5
path = [0, 0, 1, 0, 1]
beta = 1
Ta, Ya = fss_base(M, path, beta)

'''
for i in range(32):
    if Ya[i] != Yb[i]:
        print(i)
        print(Ya[i])
        print(Yb[i])
'''        

def fss_read(arr, Ta):
    temp = 0
    for x, t in zip(arr, Ta):
        if t:
            temp = temp ^ x

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', 12345))
    server_socket.listen(1)
    client_socket, _ = server_socket.accept()
    server_send_one(client_socket, temp)
    temp_other = server_receive_one(client_socket, 1024)
    client_socket.close()
    server_socket.close()
    
    sum = temp ^ temp_other
    return sum

def fss_write(Ta, Ya, arr, value_deta):
    # value_new = foq[level].writeStashValue.pop()
    # index, ifdown = foq[level].writeStashIndex.pop()
    # path = compute_path(foq, index)
    # value_ori = foq_read(level, ifdown, path, read_copy, Ta, foq)
    # value_deta = value_new ^ value_ori ^ beta
    for t, y, w in zip(Ta, Ya, arr):#Ta[level], Ya[level], foq[level].up/down
        if t:
            w = y ^ w
    return arr
