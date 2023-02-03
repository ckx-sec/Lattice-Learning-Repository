from pwn import *

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

def gen_lattice(n,k,m,p,a_list,b_list,c_list,d_list):
    ### 构造格
    # E R
    # 0 P
    M=Matrix(QQ,3*n+2)
    # 填 E
    for i in range(n+2):
        for j in range(n+2):
            if(i==j):
                M[i,j]=pow(2,k-m)
    for i in range(n+2,2*n+2):
        for j in range(n+2,2*n+2):
            if(i==j):
                M[i,j]=pow(2,2*(k-m))
    # 填 P 
    for i in range(2*n+2,3*n+2):
        for j in range(2*n+2,3*n+2):
            if(i==j):
                M[i,j]=p
    # 填 R
    k1=0
    k2=0
    k3=0
    k4=0
    for i in range(2*n+2):
        for j in range(2*n+2,3*n+2):
            if(i==0):
                M[i,j]=d_list[k1]
                k1+=1
            elif(i==1):
                M[i,j]=c_list[k2]
                k2+=1
            elif(i<n+2):
                if(i+2*n==j):
                    M[i,j]=b_list[k3]
                    k3+=1
            else:
                if(i+n==j):
                    M[i,j]=a_list[k4]
                    k4+=1
    M[0,0]=1
    matrix_overview(M)
    return M

def count_a_b_c_d_list(r_list,d_list,n):

    A_list=[0]*(n-1)
    B_list=[0]*(n-1)
    C_list=[0]*(n-1)
    D_list=[0]*(n-1)
    for i in range(n-1):
        A_list[i]=r_list[i+1]-r_list[0]
    for i in range(n-1):
        B_list[i]=r_list[i+1]*d_list[0]+1-r_list[0]*d_list[0]
    for i in range(n-1):
        C_list[i]=r_list[i+1]*d_list[i+1]-1-r_list[0]*d_list[i+1]
    for i in range(n-1):
        D_list[i]=r_list[i+1]*d_list[0]*d_list[i+1]-r_list[0]*d_list[0]*d_list[i+1]+d_list[i+1]-d_list[0]
    return A_list,B_list,C_list,D_list

proc = remote("tcp.cloud.dasctf.com", 28083)

proc.recvuntil(b'> mod =')
p = int(proc.readline())
m=1024
k=1024-328
### 判断n
# pow(2*n+2,1/2)-pow(2*n+2,1/2)*(pow(2,(k-m)*(3*n+1)/(3*n+2))*pow(p,n/(3*n+2)))  远小于0
### 本题n=14
n=14

r_list=[]
d_list=[]

for _ in range(15):
    proc.sendline('1')
    proc.recvuntil(b'> r =')
    r = int(proc.recvline())
    r_list.append(r)
    proc.recvuntil(b'> d =')
    d = int(proc.recvline())
    d_list.append(d)
    print("Received",r,d)
print(len(r_list),len(d_list))

A_list,B_list,C_list,D_list=count_a_b_c_d_list(r_list,d_list,len(r_list))
M=gen_lattice(n,k,m,p,A_list,B_list,C_list,D_list)
V=M.LLL()[0]
print(V)

e1=abs(V[1].numerator())
e2=abs(V[2].numerator())
print(e1)
print(e2)
import gmpy2
print(gmpy2.invert(int(d_list[0])+int(e1),p)-int(r_list[0]))
print(gmpy2.invert(int(d_list[1])+int(e2),p)-int(r_list[1]))
answer=gmpy2.invert(int(d_list[1])+int(e2),p)-int(r_list[1])

proc.sendline('2')
proc.sendline(str(answer)) #secret

print(proc.readline())