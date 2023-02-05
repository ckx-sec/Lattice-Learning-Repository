from pwn import *
from Crypto.Util.number import *
import time

class ECHNP:
    def __init__(self, n, p, a, b, k, h0, h_list, Xq_list, block_size=15):
        self.n = n
        self.p = p
        self.a = a
        self.b = b
        self.k = k
        self.h0 = h0
        self.h_list = h_list
        self.Xq_list = Xq_list
        self.a_list = [0]*self.n
        self.b_list = [0]*self.n
        self.c_list = [0]*self.n
        self.a0_list = [0]*self.n
        self.b0_list = [0]*self.n
        self.block_size = block_size

    def attack(self):
        self._set_config_in_lattice()
        M = self._gen_lattice()
        print("LLL...")
        T1 = time.time()
        #print("LLL result: ",M.LLL()[0])
        # V1 = abs(M.LLL()[0][0])
        # V2 = abs(M.LLL()[0][0])
        V1 = abs(M.BKZ(block_size=self.block_size)[0][0])
        V2 = abs(M.BKZ(block_size=self.block_size)[0][1])
        T2 = time.time()
        print('LLL运行时间:%s秒' % ((T2 - T1)))
        assert V2 % gcd(V2, V1) == 0
        self.e = V2/gcd(V2, V1)
        self.Xp = self.e+self.h0
        print("Xp is : ", self.e+h0)
        return self.Xp

    def _gen_lattice(self):
        #  delta^2  0   M1
        #     0   delta M2
        #     0     0   P
        ring = RealField(1)
        self.delta = int(ring(self.p/pow(2, self.k+1)).nextabove())
        #print("delta: ",self.delta)
        M = Matrix(ZZ, 3*self.n+3)

        def _gen_M1():
            M1 = Matrix(ZZ, self.n+2, self.n)
            for i in range(self.n):
                M1[0, i] = -self.c_list[i]
                M1[1, i] = -self.b_list[i]
            for i in range(2, self.n+2):
                M1[i, i-2] = -self.b0_list[i-2]
            return M1

        def _gen_M2():
            M2 = Matrix(ZZ, self.n+1, self.n)
            for i in range(self.n):
                M2[0, i] = -self.a_list[i]
            for i in range(1, self.n+1):
                M2[i, i-1] = -self.a0_list[i-1]
            return M2

        def _gen_P():
            P = Matrix(ZZ, self.n)
            for i in range(self.n):
                P[i, i] = self.p
            return P

        def _gen_Delta_Square():
            DS = Matrix(ZZ, self.n+2)
            DS[0, 0] = pow(self.delta, 3)
            for i in range(1, self.n+2):
                DS[i, i] = pow(self.delta, 2)
            return DS

        def _gen_Delta():
            D = Matrix(QQ, self.n+1)
            for i in range(self.n+1):
                D[i, i] = self.delta
            return D

        M1 = _gen_M1()
        M2 = _gen_M2()
        P = _gen_P()
        DS = _gen_Delta_Square()
        D = _gen_Delta()

        for i in range(self.n+2):
            for j in range(self.n+2):
                M[i, j] = DS[i, j]
        for i in range(self.n+1):
            for j in range(self.n+1):
                M[self.n+2+i, self.n+2+j] = D[i, j]
        for i in range(self.n):
            for j in range(self.n):
                M[2*self.n+3+i, 2*self.n+3+j] = P[i, j]
        for i in range(self.n+2):
            for j in range(self.n):
                M[i, 2*self.n+3+j] = M1[i, j]
        for i in range(self.n+1):
            for j in range(self.n):
                M[self.n+2+i, 2*self.n+3+j] = M2[i, j]

        # self._matrix_overview(M)
        return M

    def _set_config_in_lattice(self):
        for i in range(self.n):
            self.a_list[i] = self.h_list[i]-2*self.Xq_list[i]
            self.b_list[i] = 2*(self.h_list[i]*(self.h0-self.Xq_list[i])-2*self.h0 *
                                self.Xq_list[i]-self.a-pow(self.Xq_list[i], 2))
            self.c_list[i] = self.h_list[i]*pow(self.h0-self.Xq_list[i], 2)-2 * \
                ((pow(self.h0, 2)+self.a) *
                 self.Xq_list[i]+(self.a+pow(self.Xq_list[i], 2))*self.h0+2*self.b)
            self.a0_list[i] = 2*(self.h0-self.Xq_list[i])
            self.b0_list[i] = pow(self.h0-self.Xq_list[i], 2)

    def _matrix_overview(self, BB):
        for ii in range(BB.dimensions()[0]):
            a = ('%02d ' % ii)
            for jj in range(BB.dimensions()[1]):
                if BB[ii, jj] == 0:
                    a += ' '
                else:
                    a += 'X'
                if BB.dimensions()[0] < 60:
                    a += ' '
            print(a)


def collect_data_using_pwntools(host, ip, n):
    """
    收集h0、h和Xq列表
    INPUT: host,ip,n
    OUTPUT: h0,h_list,Xq_list
    """
    proc = remote(host, ip)
    proc.recvuntil(b'> mod =')
    p = int(proc.readline())
    proc.recvuntil(b'> a =')
    a = int(proc.readline())
    proc.recvuntil(b'> b =')
    b = int(proc.readline())
    proc.recvuntil(b'> R = (')
    Rx = int(proc.recvuntil(b', ', drop=True))
    Ry = int(proc.recvuntil(b')', drop=True))

    E = EllipticCurve(GF(p), [a, b])
    R = E(Rx, Ry)

    h_list = []
    Xq_list = []
    proc.sendline('1')
    proc.recvline()
    proc.sendline('0')
    h0 = int(proc.recvline())
    print("h0: ", h0)
    for i in range(1, n+1):
        proc.sendline('1')
        proc.sendline(str(i))
        Q = i*R
        h1 = int(proc.recvline())
        proc.sendline('1')
        proc.sendline(str(-i))
        h2 = int(proc.recvline())
        h_list.append(h1+h2)
        Xq_list.append(Q[0])
        #print("Received", h1, h2)

    return p, a, b, h0, h_list, Xq_list

def generate_data_locally(n, k):
    p = getPrime(1024)
    a = getPrime(200)
    b = getPrime(200)
    E = EllipticCurve(GF(p), [a, b])
    R = E.random_element()
    P = E.random_element()
    print("ECC (p,a,b): ", (p, a, b))
    print("Point R: ", (R[0], R[1]))
    print("Point P: ", (P[0], P[1]))

    h_list = []
    Xq_list = []

    def gen(t):
        O = P + t*R
        return int(O[0]) - getPrime(1024-k)
    h0 = gen(0)
    for i in range(1, n+1):
        h1 = gen(i)
        h2 = gen(-i)
        Q = i*R
        h_list.append(h1+h2)
        Xq_list.append(Q[0])
    return P[0], p, a, b, h0, h_list, Xq_list


n = 33
unknown_bits = 167
k = 1024-unknown_bits
# p,a,b,h0,h_list,Xq_list=collect_data_using_pwntools("tcp.cloud.dasctf.com",22190,n)
Xq, p, a, b, h0, h_list, Xq_list = generate_data_locally(n, k)
echnp = ECHNP(n, p, a, b, k, h0, h_list, Xq_list,25)
res = echnp.attack()
if (Xq == int(res)):
    print("success")
else:
    print("wrong")
# 1024 163 13  2s
# 1024 164 16  4s
# 1024 165 20  8s
# 1024 166 28  22s
