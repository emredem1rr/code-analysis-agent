import os
import pickle

GLOBAL_CACHE = {}

def main():
    user = input("name: ")
    query = f"SELECT * FROM users WHERE name = '{user}'"

    f = open("data.txt","w")
    f.write(user)

    eval(user)

    os.system("echo " + user)

    return query


def very_long_function(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t):
    x=1
    y=2
    z=3
    a1=4
    a2=5
    a3=6
    a4=7
    a5=8
    a6=9
    a7=10
    a8=11
    a9=12
    a10=13
    a11=14
    a12=15
    a13=16
    a14=17
    a15=18
    a16=19
    a17=20
    a18=21
    a19=22
    a20=23
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        print("deep")

    return x+y+z


def outer():
    def inner():
        print("nested")
    inner()