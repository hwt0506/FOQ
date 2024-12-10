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

def client_send(sock, arr):
    # packed_data = pickle.dumps(arr)
    packed_data = b''.join(x.to_bytes(32, byteorder='big') for x in arr)
    sock.sendall(packed_data)

def client_receive(sock, length):
    '''
    data = b""
    sock.settimeout(5.0)  # 设置超时为5秒
    while True:
        try:
            packet = sock.recv(4096)
            if not packet:
                break
            data += packet
        except socket.timeout:
            print("Receiving data timed out.")
            break
    received_data = pickle.loads(data)
    '''
    data = sock.recv(length)
    received_data = [int.from_bytes(data[i:i+32], byteorder='big') for i in range(0, 64, 32)]
    return received_data

def client_send_one(sock, arr):
    sock.sendall(str(arr).encode())

def client_receive_one(sock, length):
    data = sock.recv(length)
    a = int(data)
    return a

#exchage XOR shares of array A
#path a[M]
#value beta

def Lsb(x):
    return x & 1

# M = 15

def fss_base(M, path, beta): # M = levelCount-1

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 12345))
    '''
    a = [random.randint(1, 100) for _ in range(8)]
    mask = [random.randint(1, 100) for _ in range(8)]
    a_masked = [a[i] ^ mask[i] for i in range(8)]
    client_send(sock, mask)
    '''
    Sa_0 = get_random_bytes(16)
    # MPC
    Ta_0 = 0^(random.random() > 0.5)
    Tb_0 = 1^Ta_0
    client_send_one(sock, Tb_0)
    print('key changed')

    # 建立两个初始化为0的二维数组，各M+1行且第i行有2**i个元素
    Sa = [[0] *(2**i) for i in range(M+1)]
    Sa_ = deepcopy(Sa)
    Ta = deepcopy(Sa) # [[0] *(2**i) for i in range(M+1)]
    Tb = deepcopy(Sa) # [[0] *(2**i) for i in range(M+1)]
    theta = [0] * (M+1)
    tao = [[0] * (2) for i in range(M+1)]
    Za = deepcopy(tao) # [[0] * (2) for i in range(M+1)]
    Zb = deepcopy(tao) # [[0] * (2) for i in range(M+1)]
    Ya = [0] * (2**M)
    a = [0] + path[:M] 

    Sa[0][0] = int.from_bytes(Sa_0, byteorder='big')
    Sa_[0][0] = int.from_bytes(Sa_0, byteorder='big')
    #Ta[0][0] = int.from_bytes(Ta_0, byteorder='big')

    #Sa[0][0] = Sa_0
    Ta[0][0] = Ta_0

    key = b'\xd0\x16\x01\x0c,\xb0\xfa\xcd\xc6\xfdd\x11I$I('
    # ctr = Counter.new(128, initial_value=42)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\xc7\xc9\n/\xf1\xf4\xe4\xcf')
    for j in range(1, M+1):   #range[1, M]
        for jx in range(0, 2**(j-1)):            
            plain = Sa_[j-1][jx].to_bytes((Sa_[j-1][jx].bit_length() + 7) // 8, byteorder='big')
            Sa[j][2*jx] = int.from_bytes(cipher.encrypt(plain), byteorder='big')
            Sa[j][2*jx+1] = int.from_bytes(cipher.encrypt(plain), byteorder='big')
            
            Za[j][0]= Za[j][0] ^ Sa[j][2*jx]
            Za[j][1]= Za[j][1] ^ Sa[j][2*jx+1]
        
        client_send(sock, Za[j])
        Zb[j]= client_receive(sock, 4096)

        #MPC
        theta[j] = Za[j][1^a[j]] ^ Zb[j][1^a[j]]
        tao[j][0] = Lsb(Za[j][0]) ^ Lsb(Zb[j][0]) ^ a[j] ^ 1
        tao[j][1] = Lsb(Za[j][1]) ^ Lsb(Zb[j][1]) ^ a[j]
        
        for jx in range(0, 2**j):
            temp = math.floor(jx/2)
            Sa_[j][jx] = Sa[j][jx]
            Ta[j][jx] = Lsb(Sa[j][jx])
            if Ta[j-1][temp]:
                Sa_[j][jx] ^= theta[j]
                Ta[j][jx] ^= tao[j][Lsb(jx)]
            
    #MPC        
    Ga = Za[M][a[j]] ^ Zb[M][a[j]] ^ theta[M] ^ beta

    sock.close()
    for jx in range(0, 2**M):
        Ya[jx] = Sa_[M][jx] 
        if Ta[M][jx]:
            Ya[jx] ^= Ga
        
        # fss_read(arr, Ta[j])
        # fss_write()
        # compare
        # mpc(如binary search) and change path
        
    return Ta, Ya

def fss_multi(M, path, beta): #beta有levelCount-1个元素

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 12345))
    '''
    a = [random.randint(1, 100) for _ in range(8)]
    mask = [random.randint(1, 100) for _ in range(8)]
    a_masked = [a[i] ^ mask[i] for i in range(8)]
    client_send(sock, mask)
    '''
    Sa_0 = get_random_bytes(16)
    # MPC
    Ta_0 = 0^(random.random() > 0.5)
    Tb_0 = 1^Ta_0
    client_send_one(sock, Tb_0)
    print('key changed')

    # 建立两个初始化为0的二维数组，各M+1行且第i行有2**i个元素
    Sa = [[0] *(2**i) for i in range(M+1)]
    Sa_ = deepcopy(Sa)
    Ta = deepcopy(Sa) # [[0] *(2**i) for i in range(M+1)]
    Tb = deepcopy(Sa) # [[0] *(2**i) for i in range(M+1)]
    theta = [0] * (M+1)
    tao = [[0] * (2) for i in range(M+1)]
    Za = deepcopy(tao) # [[0] * (2) for i in range(M+1)]
    Zb = deepcopy(tao) # [[0] * (2) for i in range(M+1)]
    Ya = deepcopy(Sa)
    a = [0] + path[:M] 
    beta = [0] + beta[:M]
    Ga = [0]*(M+1)
    
    Sa[0][0] = int.from_bytes(Sa_0, byteorder='big')
    Sa_[0][0] = int.from_bytes(Sa_0, byteorder='big')
    #Ta[0][0] = int.from_bytes(Ta_0, byteorder='big')

    #Sa[0][0] = Sa_0
    Ta[0][0] = Ta_0

    key = b'\xd0\x16\x01\x0c,\xb0\xfa\xcd\xc6\xfdd\x11I$I('
    # ctr = Counter.new(128, initial_value=42)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'\xc7\xc9\n/\xf1\xf4\xe4\xcf')
    for j in range(1, M+1):   #range[1, M]
        for jx in range(0, 2**(j-1)):            
            plain = Sa_[j-1][jx].to_bytes((Sa_[j-1][jx].bit_length() + 7) // 8, byteorder='big')
            Sa[j][2*jx] = int.from_bytes(cipher.encrypt(plain), byteorder='big')
            Sa[j][2*jx+1] = int.from_bytes(cipher.encrypt(plain), byteorder='big')
            
            Za[j][0]= Za[j][0] ^ Sa[j][2*jx]
            Za[j][1]= Za[j][1] ^ Sa[j][2*jx+1]
        
        client_send(sock, Za[j])
        Zb[j]= client_receive(sock, 4096)

        #MPC
        theta[j] = Za[j][1^a[j]] ^ Zb[j][1^a[j]]
        tao[j][0] = Lsb(Za[j][0]) ^ Lsb(Zb[j][0]) ^ a[j] ^ 1
        tao[j][1] = Lsb(Za[j][1]) ^ Lsb(Zb[j][1]) ^ a[j]
        
        for jx in range(0, 2**j):
            temp = math.floor(jx/2)
            Sa_[j][jx] = Sa[j][jx]
            Ta[j][jx] = Lsb(Sa[j][jx])
            if Ta[j-1][temp]:
                Sa_[j][jx] ^= theta[j]
                Ta[j][jx] ^= tao[j][Lsb(jx)]
            
        #MPC        
        Ga[j] = Za[j][a[j]] ^ Zb[j][a[j]] ^ theta[j] ^ beta[j]

        sock.close()
        for jx in range(0, 2**j):
            Ya[j][jx] = Sa_[j][jx] 
            if Ta[j][jx]:
                Ya[j][jx] ^= Ga[j]
        
        # fss_read(arr, Ta[j])
        # fss_write()
        # compare
        # mpc(如binary search) and change path
        
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
    for x, y in zip(arr, Ta):
        if y:
            temp = temp ^ x

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', 12345))
    client_send_one(sock, temp)
    temp_other = client_receive_one(sock, 1024)
    sock.close()
    
    sum = temp ^ temp_other
    return sum

def fss_write(Ta, Ya, arr):
    # value_new = foq[level].writeStashValue.pop()
    # index, ifdown = foq[level].writeStashIndex.pop()
    # path = compute_path(foq, index)
    # value_ori = foq_read(level, ifdown, path, read_copy, Ta, foq)
    # value_deta = value_new ^ value_ori ^ beta
    for t, y, w in zip(Ta, Ya, arr):#Ta[level], Ya[level], foq[level].up/down
        if t:
            w = y ^ w

    return arr