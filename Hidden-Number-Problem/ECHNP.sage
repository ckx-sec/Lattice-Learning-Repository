from pwn import *

context.log_level = 'DEBUG'


def matrix_overview(BB):
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


def gen_lattice(n, p, k, a_list, b_list, c_list, a0_list, b0_list):
    #  delta^2  0   M1
    #     0   delta M2
    #     0     0   P

    ring = RealField(1)
    delta = int(ring(p/pow(2, k+1)).nextabove())
    print("delta: ",delta)
    M = Matrix(QQ, 3*n+3)

    def gen_M1(b_list, c_list, b0_list):
        M1 = Matrix(QQ, n+2, n)
        for i in range(n):
            M1[0, i] = -c_list[i]
            M1[1, i] = -b_list[i]
        for i in range(2, n+2):
            M1[i, i-2] = -b0_list[i-2]
        return M1

    def gen_M2(a_list, a0_list):
        M2 = Matrix(QQ, n+1, n)
        for i in range(n):
            M2[0, i] = -a_list[i]
        for i in range(1, n+1):
            M2[i, i-1] = -a0_list[i-1]
        return M2

    def gen_P(p):
        P = Matrix(QQ, n)
        for i in range(n):
            P[i, i] = p
        return P

    def gen_Delta_Square(delta):
        DS = Matrix(QQ, n+2)
        DS[0, 0] = pow(delta, 3)
        for i in range(1, n+2):
            DS[i, i] = pow(delta, 2)
        return DS

    def gen_Delta(delta):
        D = Matrix(QQ, n+1)
        for i in range(n+1):
            D[i, i] = delta
        return D

    M1 = gen_M1(b_list, c_list, b0_list)
    M2 = gen_M2(a_list, a0_list)
    P = gen_P(p)
    DS = gen_Delta_Square(delta)
    D = gen_Delta(delta)

    for i in range(n+2):
        for j in range(n+2):
            M[i, j] = DS[i, j]
    for i in range(n+1):
        for j in range(n+1):
            M[n+2+i, n+2+j] = D[i, j]
    for i in range(n):
        for j in range(n):
            M[2*n+3+i, 2*n+3+j] = P[i, j]
    for i in range(n+2):
        for j in range(n):
            M[i, 2*n+3+j] = M1[i, j]
    for i in range(n+1):
        for j in range(n):
            M[n+2+i, 2*n+3+j] = M2[i, j]

    matrix_overview(M)
    print(M[0,0])
    print(M[1,1])
    print(M[16,16])
    print(M[-1,-1])
    return M


def collect_data(n, a, b, h0, h_list, Xq_list):
    # k 需要 > (5/6)*log(p)
    a_list = [0]*n
    b_list = [0]*n
    c_list = [0]*n
    a0_list = [0]*n
    b0_list = [0]*n

    for i in range(n):
        a_list[i] = h_list[i]-2*Xq_list[i]
        b_list[i] = 2*(h_list[i]*(h0-Xq_list[i])-2*h0 *
                       Xq_list[i]-a-pow(Xq_list[i], 2))
        c_list[i] = h_list[i]*pow(h0-Xq_list[i], 2)-2 * \
            ((pow(h0, 2)+a)*Xq_list[i]+(a+pow(Xq_list[i], 2))*h0+2*b)
        a0_list[i] = 2*(h0-Xq_list[i])
        b0_list[i] = pow(h0-Xq_list[i], 2)

    return a_list, b_list, c_list, a0_list, b0_list


def attack(n, p, k, a, b, h0, h_list, Xq_list):
    a_list, b_list, c_list, a0_list, b0_list = collect_data(
        n, a, b, h0, h_list, Xq_list)
    M = gen_lattice(n, p, k, a_list, b_list, c_list, a0_list, b0_list)
    print(M.LLL()[0])
    V1=abs(M.LLL()[0][0])
    V2=abs(M.LLL()[0][1])
    assert V2%gcd(V2,V1)==0
    answer=V2/gcd(V2,V1)
    print(answer)
    return answer


proc = remote("tcp.cloud.dasctf.com", 22190)
proc.recvuntil(b'> mod =')
p = int(proc.readline())
proc.recvuntil(b'> a =')
a = int(proc.readline())
proc.recvuntil(b'> b =')
b = int(proc.readline())
proc.recvuntil(b'> R = (')
Rx = int(proc.recvuntil(b', ', drop=True))
Ry = int(proc.recvuntil(b')', drop=True))

E = EllipticCurve(GF(p),[a,b])
R = E(Rx,Ry)
n = 14
k = 1024-163
h_list = []
Xq_list = []
proc.sendline('1')
proc.recvline()
proc.sendline('0')
h0 = int(proc.recvline())
print("h0: ",h0)
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
    print("Received", h1, h2)


e=attack(n, p, k, a, b, h0, h_list, Xq_list)
print("Xp is : ",e+h0)
proc.sendline('2')
proc.sendline(str(e+h0))
print(proc.recvline())
